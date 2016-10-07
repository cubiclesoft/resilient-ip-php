<?php
	// Resilient IP server.
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";
	require_once $rootpath . "/support/resilient_ip_functions.php";

	$config = RESIP_LoadConfig();

	if (!isset($config["whitelist"]))  CLI::DisplayError("Configuration is incomplete or missing.  Run 'install.php' first.");

	define("MAX_UDP_PACKET", 512);
	define("MAX_FRAGMENTS", 128);

	require_once $rootpath . "/support/web_server.php";

	$webserver = new WebServer();

	echo "Starting server...\n";
	$result = $webserver->Start($config["host"], $config["session_port"], (isset($config["sslopts"]) ? $config["sslopts"] : false));
	if (!$result["success"])  CLI::DisplayError("Unable to start Session server.", $result);

	// Main UDP/IP server.
	$context = stream_context_create();
	$udpfp = stream_socket_server("udp://" . $config["host"] . ":" . $config["resip_port"], $errornum, $errorstr, STREAM_SERVER_BIND, $context);
	if ($udpfp === false)  CLI::DisplayError("Unable to start resilient IP server.", array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"));

	// Enable non-blocking mode.
	stream_set_blocking($udpfp, 0);

	// Fallback TCP/IP server.
	$context = stream_context_create();
	$tcpfp = stream_socket_server("tcp://" . $config["host"] . ":" . $config["resip_port"], $errornum, $errorstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
	if ($tcpfp === false)  CLI::DisplayError("Unable to start resilient IP server.", array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"));

	// Enable non-blocking mode.
	stream_set_blocking($tcpfp, 0);

	// Set up encryption.
	require_once $rootpath . "/support/phpseclib/Crypt/Base.php";
	require_once $rootpath . "/support/phpseclib/Crypt/Rijndael.php";
	require_once $rootpath . "/support/phpseclib/Crypt/AES.php";

	require_once $rootpath . "/support/ipaddr.php";
	require_once $rootpath . "/support/deflate_stream.php";

	if (!DeflateStream::IsSupported())  CB_DisplayError("One or more functions are not available for data compression.  Try enabling the 'zlib' module.");

	// Generate the resilient IP server's encryption key.
	$rng = new CSPRNG(true);
	$masterkeys = array(
		"key1" => $rng->GetBytes(32),
		"iv1" => $rng->GetBytes(16),
		"key2" => $rng->GetBytes(32),
		"iv2" => $rng->GetBytes(16)
	);

	$masterkeysdist = array(
		"key1" => bin2hex($masterkeys["key1"]),
		"iv1" => bin2hex($masterkeys["iv1"]),
		"key2" => bin2hex($masterkeys["key2"]),
		"iv2" => bin2hex($masterkeys["iv2"])
	);

	$mastercipher1 = new Crypt_AES();
	$mastercipher1->setKey($masterkeys["key1"]);
	$mastercipher1->setIV($masterkeys["iv1"]);
	$mastercipher1->disablePadding();

	$mastercipher2 = new Crypt_AES();
	$mastercipher2->setKey($masterkeys["key2"]);
	$mastercipher2->setIV($masterkeys["iv2"]);
	$mastercipher2->disablePadding();

	echo "Ready.\n";

	$serverts = time();
	$rng = new CSPRNG();
	$sessions = array();
	$nextsession = 1;

	function CreateChannel($id, $compress)
	{
		$channel = new stdClass();
		$channel->id = $id;
		$channel->fp = false;
		$channel->fpaddr = "";
		$channel->protocol = "";
		$channel->readdata = array();
		$channel->compress = $compress;
		$channel->readopen = true;
		$channel->readpackets = array();
		if (!$id)  $channel->readunordered = array();
		$channel->readack = array();
		$channel->startread = 1;  // Starting number for reading packets.
		$channel->nextread = 1;  // Expected next packet number.
		$channel->lastread = false;
		$channel->writeopen = true;
		$channel->writepackets = array();
		$channel->nextwrite = 1;  // Next packet number to write.
		if (!$id)  $channel->unorderedwrite = -1;  // Unordered packet number to write.

		return $channel;
	}

	function ProcessAPI($client, $data)
	{
		global $config, $masterkeysdist, $serverts, $rng, $sessions, $nextsession;

		$url = HTTP::ExtractURL($client->url);
		$path = explode("/", $url["path"]);

		if (count($path) < 4 || $path[1] !== "resip")  return array("success" => false, "error" => "Invalid API call.", "errorcode" => "invalid_api_call");

		if ($path[3] === "server")
		{
			if ($path[4] === "info")
			{
				if ($client->request["method"] !== "GET")  return array("success" => false, "error" => "GET request required for 'server_info'", "errorcode" => "use_get_request");

				return array("success" => true, "started" => $serverts, "current" => time());
			}
		}
		else if ($path[3] === "session")
		{
			if ($path[4] === "start")
			{
				if ($client->request["method"] !== "POST")  return array("success" => false, "error" => "POST request required for 'start_session'", "errorcode" => "use_post_request");
				if (!isset($data["hash"]))  return array("success" => false, "error" => "Missing 'hash'.", "errorcode" => "missing_hash");

				$data["hash"] = strtolower($data["hash"]);

				// Overhead:  SHA-1 is 3.9%, MD5 is 3.1%.
				// SHA-1 HMAC is fairly balanced between data integrity, hash security, and overhead.  Clients should prefer it over MD5 HMAC.
				if ($data["hash"] === "sha1")  $hashsize = 20;
				else if ($data["hash"] === "md5")  $hashsize = 16;
				else  return array("success" => false, "error" => "Invalid 'hash' specified.", "errorcode" => "invalid_hash");

				$sessionkeys = array(
					"key1" => $rng->GetBytes(32),
					"iv1" => $rng->GetBytes(16),
					"key2" => $rng->GetBytes(32),
					"iv2" => $rng->GetBytes(16),
					"sign" => $rng->GetBytes($hashsize)
				);

				$sessionkeysdist = array(
					"key1" => bin2hex($sessionkeys["key1"]),
					"iv1" => bin2hex($sessionkeys["iv1"]),
					"key2" => bin2hex($sessionkeys["key2"]),
					"iv2" => bin2hex($sessionkeys["iv2"]),
					"sign" => bin2hex($sessionkeys["sign"])
				);

				$session = new stdClass();
				$session->id = $nextsession;
				$session->hashmethod = $data["hash"];
				$session->hashsize = $hashsize;

				$session->cipher3 = new Crypt_AES();
				$session->cipher3->setKey($sessionkeys["key1"]);
				$session->cipher3->setIV($sessionkeys["iv1"]);
				$session->cipher3->disablePadding();

				$session->cipher4 = new Crypt_AES();
				$session->cipher4->setKey($sessionkeys["key2"]);
				$session->cipher4->setIV($sessionkeys["iv2"]);
				$session->cipher4->disablePadding();

				$session->sign = $sessionkeys["sign"];

				$session->channels = array();
				$session->clients = array();
				$session->nextack = microtime(true) + .5;

				// Implicit channel 0.
				$session->channels[0] = CreateChannel(0, false);

				$sessions[$nextsession] = $session;
				$nextsession++;

				return array("success" => true, "started" => $serverts, "current" => time(), "packet_size" => MAX_UDP_PACKET, "max_fragments" => MAX_FRAGMENTS, "master" => $masterkeysdist, "session" => $sessionkeysdist, "session_id" => $session->id);
			}
		}

		return array("success" => false, "error" => "Invalid API call.", "errorcode" => "invalid_api_call");
	}


	function ExtractPacket($data, $fixedsessionid = false)
	{
		global $mastercipher1, $mastercipher2, $sessions;

echo "---- Received Packet (" . microtime(true) . ") ----\n";
		if (strlen($data) !== MAX_UDP_PACKET)  return false;

		// Unwrap the session encrypted data block.
		// Decrypt the block.
		$data = $mastercipher2->decrypt($data);

		// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
		$data = substr($data, 1) . substr($data, 0, 1);

		// Decrypt the block again.
		$data = $mastercipher1->decrypt($data);

		// Handle packet type.
		$tempbyte = ord($data{1});
		$packettype = ($tempbyte & 0x0F);
echo "  Packet type:  " . $packettype . "\n";
		if ($packettype !== 0)  return false;

		// Verify session ID.
		$sessionid = RESIP_UnpackInt(substr($data, 2, 4));
echo "  Session ID:  " . $sessionid . "\n";
		if ($fixedsessionid !== false && $sessionid !== $fixedsessionid)  return false;
		if (!isset($sessions[$sessionid]))  return false;
		$session = $sessions[$sessionid];

		// Verify the hash.
		$hash = substr($data, -$session->hashsize);
		$data = substr($data, 6, MAX_UDP_PACKET - 32);
		if (hash_hmac($session->hashmethod, $data, $session->sign, true) !== $hash)  return false;

		// Extract the session data.
		// Decrypt the block.
		$data = $session->cipher4->decrypt($data);

		// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
		$data = substr($data, 1) . substr($data, 0, 1);

		// Decrypt the block again.
		$data = $session->cipher3->decrypt($data);

		// Verify client bit.
		$tempbyte = ord($data{1});
		if (($tempbyte & 0x80) !== 0)  return false;

		// Extract compression, fragmentation, and size details.
		$compressed = (($tempbyte & 0x40) !== 0);
		$fragment = (($tempbyte & 0x20) !== 0);
		$channelbytes = (($tempbyte >> 3) & 0x03) + 1;
		$packetnumbytes = ($tempbyte & 0x07) + 1;

		// Extract channel, packet number, and data size.
		$channelnum = RESIP_UnpackInt(substr($data, 2, $channelbytes));
echo "  Channel:  " . $channelnum . "\n";
		if ($channelnum === 0 && $fragment)  return false;
		if (!isset($session->channels[$channelnum]))  return false;
		$channel = $session->channels[$channelnum];
		if ($compressed && !$channel->compress)  return false;
		$x = 2 + $channelbytes;

		// Ignore packets that have already been received and/or processed.
		$packetnum = RESIP_UnpackInt(substr($data, $x, $packetnumbytes));
echo "  Packet number:  " . $packetnum . "\n";
		if (!$packetnum && ($channelnum || $fragment))  return false;
		if ($packetnum > 0 && ($packetnum < $channel->startread || isset($channel->readpackets[$packetnum])))
		{
			$channel->readack[$packetnum] = true;

			return false;
		}
		if ($channel->lastread !== false && $packetnum > $channel->lastread)  return false;
		$x += $packetnumbytes;

		$datasize = RESIP_UnpackInt(substr($data, $x, 2));
		$x += 2;

		if ($x + $datasize > strlen($data))  return false;

		$data = substr($data, $x, $datasize);
echo "  " . rtrim(str_replace("\n", "\n  ", CLI::GetHexDump($data))) . "\n";

		// Append the packet to the correct channel and adjust tracking variables.
		$packet = array(
			"compressed" => $compressed,
			"fragment" => $fragment,
			"data" => $data
		);

		if (!$packetnum)  $channel->readunordered[] = $packet;
		else
		{
			$channel->readpackets[$packetnum] = $packet;

			// Register to send an acknowledgement packet.  This is somewhat spurious for TCP/IP resilient IP server connections
			// but it does help pick up where the packets ended during reestablishment of a lost connection.
			$channel->readack[$packetnum] = true;

			if ($channel->nextread <= $packetnum)  $channel->nextread = $packetnum + 1;
		}

		return array("session" => $session, "channel" => $channel);
	}

	function ReadRESIPTCPPackets($session, $client)
	{
		global $tcpclients;

		do
		{
			if (strlen($client->readdata) < MAX_UDP_PACKET)
			{
				$data = @fread($client->fp, 65536);
				if ($data === false || ($data === "" && feof($client->fp)))
				{
					@fclose($client->fp);

					if ($session !== false)  unset($session->clients[$client->id]);
					else  unset($tcpclients[$client->id]);

					return;
				}
			}

			$client->readdata .= $data;
			if (strlen($client->readdata) < MAX_UDP_PACKET)  $data = false;
			else
			{
				$data = substr($client->readdata, 0, MAX_UDP_PACKET);
				$client->readdata = substr($client->readdata, MAX_UDP_PACKET);
			}

			if ($data !== false && $data !== "")
			{
				$result = ExtractPacket($data, ($session !== false ? $session->id : false));
				if ($result !== false && $session === false)
				{
					$session = $result["session"];
					$session->clients[$client->id] = $client;

					unset($tcpclients[$client->id]);
				}
			}
		} while ($data !== false && $data !== "");
	}

	function MaxFragmentSize($channel)
	{
		return MAX_UDP_PACKET - 32 - 5 - RESIP_GetBitsIntSize($channel->id) - RESIP_GetBitsIntSize($channel->nextwrite);
	}

	function WriteChannelData($session, $channel, $data, $ack = true)
	{
		global $rng, $mastercipher1, $mastercipher2, $writeudppackets;

		$maxsize = MaxFragmentSize($channel);
		$chunks = str_split($data, $maxsize * MAX_FRAGMENTS);

		foreach ($chunks as $data)
		{
			// Compress the data at once.
			if ($channel->compress)  $data = DeflateStream::Compress($data);

			// Split the data into fragments.
			$maxsize = MaxFragmentSize($channel);
			$x = 0;
			$y = strlen($data);
			while ($x < $y)
			{
				$size = ($x + $maxsize < $y ? $maxsize : $y - $x);

				// Build the session encrypted data block.
				// Random byte for a block offset.
				$data2 = $rng->GetBytes(1);

				// 1 bit server (1), 1 bit compressed, 1 bit message continued (fragmented data), 2 bits channel size, 3 bits packet number size.
				$data2 .= chr(0x80 | ($channel->compress ? 0x40 : 0x00) | ($x + $size < $y ? 0x20 : 0x00) | (RESIP_GetBitsIntSize($channel->id) << 3) | RESIP_GetBitsIntSize($ack ? $channel->nextwrite : 0));

				// Channel.
				$data2 .= RESIP_PackInt($channel->id);

				// Packet number.
				$data2 .= RESIP_PackInt($ack ? $channel->nextwrite : 0);

				// Packet data size.
				$data2 .= pack("n", $size);

				// Packet data.
				$data2 .= substr($data, $x, $size);

				// Pad out to max size.
				$data2 .= $rng->GetBytes(MAX_UDP_PACKET - 32 - strlen($data2));

				// Encrypt the block.
				$data2 = $session->cipher3->encrypt($data2);

				// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
				$data2 = substr($data2, -1) . substr($data2, 0, -1);

				// Encrypt the block again.
				$data2 = $session->cipher4->encrypt($data2);


				// Wrap the session encrypted data block.
				// Random byte for a block offset.
				$data3 = $rng->GetBytes(1);

				// 4 bits reserved, 4 bits packet type (0).
				$data3 .= "\x00";

				// Session ID.
				$data3 .= pack("N", $session->id);

				// Session encrypted data.
				$data3 .= $data2;

				// Add random bytes based on a fixed data size.
				$data3 .= $rng->GetBytes(32 - $session->hashsize - 6);

				// Sign the encrypted data packet.
				$data3 .= hash_hmac($session->hashmethod, $data2, $session->sign, true);

				// Encrypt the block.
				$data3 = $mastercipher1->encrypt($data3);

				// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
				$data3 = substr($data3, -1) . substr($data3, 0, -1);

				// Encrypt the block again.
				$data3 = $mastercipher2->encrypt($data3);


				// Append to channel write queue for resending.
				if ($ack)
				{
					$writenum = $channel->nextwrite;
					$channel->nextwrite++;
				}
				else
				{
					$writenum = $channel->unorderedwrite;
					$channel->unorderedwrite--;
				}
				$channel->writepackets[$writenum] = array("data" => $data3, "ack" => $ack, "ts" => -1, "dist" => 3, "udp" => 0);

				// Queue for sending.
				foreach ($session->clients as $client)
				{
					if ($client->protocol === "tcp")  $client->writedata[] = array("data" => $data3, "chid" => $channel->id, "num" => $writenum);
					else if ($client->protocol === "udp")
					{
						$writeudppackets[] = array("sid" => $session->id, "chid" => $channel->id, "clid" => $client->id, "num" => $writenum);

						$channel->writepackets[$writenum]["udp"]++;
					}
				}

				$x += $size;
			}
		}
	}

	function StopChannel($session, $channel)
	{
		// Don't allow the command channel to be stopped and ignore duplicate stop requests.
		if (!$channel->id || !$channel->writeopen)  return false;

		// Command channel (0) first byte:  3 bits reserved, 5 bits command.
		// Stop channel command (2).
		$data = "\x02";

		// Next byte:  3 bits reserved, 2 bits channel size, 3 bits last packet size.
		$data .= chr((RESIP_GetBitsIntSize($channel->id) << 3) | RESIP_GetBitsIntSize($channel->nextwrite - 1));

		// Channel.
		$data .= RESIP_PackInt($channel->id);

		// Last packet number.
		$data .= RESIP_PackInt($channel->nextwrite - 1);

		WriteChannelData($session, $session->channels[0], $data);
echo "Stopped channel " . $session->id . ":" . $channel->id . ".\n";

		$channel->writeopen = false;

		return true;
	}

	function AppendACKRange(&$data, $startnum, $lastnum, &$channelused, $session, $channel, $maxsize)
	{
		// Info byte:  1 bit (1), 1 bit range, 3 bits packet number size, 3 bits packet number size (unused when 'range' is 0).
		$data2 = chr(0x80 | ($startnum !== $lastnum ? 0x40 : 0x00) | (RESIP_GetBitsIntSize($startnum) << 3) | ($startnum !== $lastnum ? RESIP_GetBitsIntSize($lastnum) : 0x00));

		// Start packet number.
		$data2 .= RESIP_PackInt($startnum);

		// Last packet number.
		if ($startnum !== $lastnum)  $data2 .= RESIP_PackInt($lastnum);

		if (!$channelused)
		{
			// Next byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
			$data3 = chr(RESIP_GetBitsIntSize($channel->id));

			// Channel.
			$data3 .= RESIP_PackInt($channel->id);

			$data2 = $data3 . $data2;

			$channelused = true;
		}

		if (strlen($data) + strlen($data2) > $maxsize)
		{
			// Write out the packet and reset for a new packet.
			// Command channel (0) first byte:  3 bits reserved, 5 bits command.
			// ACK channel command (3).
			WriteChannelData($session, $session->channels[0], "\x03" . $data, false);
echo "Queued ACK packet.\n";

			$data = "";

			if (count($session->channels[0]->writepackets) >= 64)  return false;

			// Next byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
			$data3 .= chr(RESIP_GetBitsIntSize($channel->id));

			// Channel.
			$data3 .= RESIP_PackInt($channel->id);

			$data2 = $data3 . $data2;
		}

		$data .= $data2;

		return true;
	}

	function ProcessCommandChannelPacket($session, $data)
	{
		global $config;

		$y = strlen($data);
		if ($y < 1)  return false;

		// Extract the command.
		$command = ord($data{0}) & 0x1F;
echo "Received command:  " . $command . "\n";

		switch ($command)
		{
			case 1:
			{
				// Start channel.
				if ($y < 2)  return false;

				// Next byte:  1 bit compression support, 1 bit fragmentation support (1), 2 bits channel size, 2 bits IP version (0 = IPv4, 1 = IPv6), 2 bits port number size.
				$tempbyte = ord($data{1});
				$compress = (($tempbyte & 0x80) != 0);
				$fragment = (($tempbyte & 0x40) != 0);
				if (!$fragment)  return false;
				$channelbytes = (($tempbyte >> 4) & 0x03) + 1;
				$ipver = (($tempbyte >> 2) & 0x03);
				if ($ipver === 0)  $ipbytes = 4;
				else if ($ipver === 1)  $ipbytes = 16;
				else  return false;
				$portbytes = ($tempbyte & 0x03) + 1;

				if ($y < 2 + $channelbytes + 1 + $ipbytes + $portbytes)  return false;

				// Channel number.
				$channelnum = RESIP_UnpackInt(substr($data, 2, $channelbytes));
				if (isset($session->channels[$channelnum]))  return false;
				$x = 2 + $channelbytes;

				// Create the channel.
				$channel = CreateChannel($channelnum, $compress);
				$session->channels[$channelnum] = $channel;

				// Next byte:  Protocol number.
				// TCP is 6 (0x06), UDP is 17 (0x11), ICMP is 1 (0x01).
				// ICMP is not supported.
				$protocol = ord($data{$x});
				if ($protocol === 6)  $protocol = "tcp";
				else if ($protocol === 17)  $protocol = "udp";
				else
				{
					$channel->readopen = false;
					StopChannel($session, $channel);

					return false;
				}
				$x++;

				// IP address.
				if ($ipver === 0)
				{
					$ipaddr = ord($data{$x}) . "." . ord($data{$x + 1}) . "." . ord($data{$x + 2}) . "." . ord($data{$x + 3});
					$clientip = $ipaddr;
					$x += 4;
				}
				else if ($ipver === 1)
				{
					$ipaddr = implode(":", str_split(bin2hex(substr($data, $x, 16)), 4));
					$clientip = "[" . $ipaddr . "]";
					$x += 16;
				}
echo $ipaddr . "\n";

				// Check security restrictions.
				$ipaddr2 = IPAddr::NormalizeIP($ipaddr);
				if (IPAddr::IsMatch("0.0.0.0", $ipaddr2) || IPAddr::IsMatch("0000:0000:0000:0000:0000:0000:0000:0000", $ipaddr2))
				{
echo "Stop: 1\n";
					$channel->readopen = false;
					StopChannel($session, $channel);

					return false;
				}
				$found = false;
				foreach ($config["whitelist"] as $pattern)
				{
					if (IPAddr::IsMatch($pattern, $ipaddr2))  $found = true;
				}

				if (!$found && $config["allow_internet"])
				{
					$local = (IPAddr::IsMatch("127.0.0.*", $ipaddr2) || IPAddr::IsMatch("10.*.*.*", $ipaddr2) || IPAddr::IsMatch("172.16-31.*.*", $ipaddr2) || IPAddr::IsMatch("192.168.*.*", $ipaddr2) || IPAddr::IsMatch("0000:0000:0000:0000:0000:0000:0000:0001", $ipaddr2) || IPAddr::IsMatch("FD00-FDFF:*:*:*:*:*:*:*", $ipaddr2));

					if (!$local)  $found = true;
				}

				if (!$found)
				{
echo "Stop: 2\n";
					$channel->readopen = false;
					StopChannel($session, $channel);

					return false;
				}

				// Port number.
				$port = RESIP_UnpackInt(substr($data, $x, $portbytes));
				if ($port < 1 || $port > 65535)
				{
echo "Stop: 3\n";
					$channel->readopen = false;
					StopChannel($session, $channel);

					return false;
				}

				// Initialize socket connection.
				$context = stream_context_create();
				$channel->protocol = $protocol;
				$channel->fpaddr = $clientip . ":" . $port;
echo $channel->protocol . "://" . $channel->fpaddr . "\n";
				if ($channel->protocol === "tcp")  $channel->fp = @stream_socket_client("tcp://" . $channel->fpaddr, $errornum, $errorstr, 10, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT, $context);
				else if ($channel->protocol === "udp")  $channel->fp = @stream_socket_server("udp://" . ($ipver === 0 ? "0.0.0.0" : "[::0]") . ":0", $errornum, $errorstr, STREAM_SERVER_BIND, $context);

				if ($channel->fp === false)
				{
echo "Stop: 4\n";
					$channel->readopen = false;
					StopChannel($session, $channel);

					return false;
				}

				// Queue the response packet that target connection initialization was successful.

				// Command channel (0) first byte:  3 bits reserved, 5 bits command.
				// Start channel response command (1).
				$data = "\x01";

				// Next byte:  6 bits reserved, 2 bits channel size.
				$data .= chr(RESIP_GetBitsIntSize($channel->id));

				// Channel.
				$data .= RESIP_PackInt($channel->id);

				WriteChannelData($session, $session->channels[0], $data, false);
echo "Queued start channel response for session " . $session->id . ".\n";

				return true;
			}
			case 2:
			{
				// Stop channel.
				if ($y < 2)  return false;

				// Next byte:  3 bits reserved, 2 bits channel size, 3 bits last packet size.
				$tempbyte = ord($data{1});
				$channelbytes = (($tempbyte >> 3) & 0x03) + 1;
				$packetnumbytes = ($tempbyte & 0x07) + 1;

				if ($y < 2 + $channelbytes + $packetnumbytes)  return false;

				$channelnum = RESIP_UnpackInt(substr($data, 2, $channelbytes));
				if (!$channelnum || !isset($session->channels[$channelnum]))  return false;
				$channel = $session->channels[$channelnum];
				$x = 2 + $channelbytes;

				$channel->lastread = RESIP_UnpackInt(substr($data, $x, $packetnumbytes)) + 1;

				StopChannel($session, $channel);

				return true;
			}
			case 3:
			{
				// ACK.
				if ($y < 2)  return false;

				$x = 1;
				$channelnum = false;
				$channel = false;
				while ($x < $y)
				{
					// First bit differentiates whether the current byte is a channel byte or an information byte.
					$tempbyte = ord($data{$x});
					$x++;

					if ($tempbyte & 0x80)
					{
						// Info byte:  1 bit (1), 1 bit range, 3 bits packet number size, 3 bits packet number size (unused when 'range' is 0).
						if ($channelnum === false)  return false;
						$range = (($tempbyte & 0x40) !== 0);
						$startnumbytes = (($tempbyte >> 3) & 0x07) + 1;
						$lastnumbytes = ($range ? ($tempbyte & 0x07) + 1 : 0);
						if ($y < $x + $startnumbytes + $lastnumbytes)  return false;

						$startnum = RESIP_UnpackInt(substr($data, $x, $startnumbytes));
						$x += $startnumbytes;

						$lastnum = ($range ? RESIP_UnpackInt(substr($data, $x, $lastnumbytes)) : $startnum);
						$x += $lastnumbytes;

						if ($channel !== false)
						{
							for (; $startnum <= $lastnum; $startnum++)
							{
								unset($channel->writepackets[$startnum]);
							}
						}
					}
					else
					{
						// Channel byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
						$channelbytes = ($tempbyte & 0x03) + 1;

						if ($y < $x + $channelbytes)  return false;

						$channelnum = RESIP_UnpackInt(substr($data, $x, $channelbytes));
						$x += $channelbytes;
						$channel = (isset($session->channels[$channelnum]) ? $session->channels[$channelnum] : false);
					}
				}

				return true;
			}
			case 4:
			{
				// Keep alive.

				// Command channel (0) first byte:  3 bits reserved, 5 bits command.
				// Keep alive channel command (4).
				WriteChannelData($session, $session->channels[0], "\x04", false);
echo "Queued keep-alive packet for session " . $session->id . ".\n";

				return true;
			}
			case 5:
			{
				// Terminate channel.  Client is requesting immediate forced channel termination.
				if ($y < 2)  return false;

				// Next byte:  6 bits reserved, 2 bits channel size.
				$tempbyte = ord($data{1});
				$channelbytes = ($tempbyte & 0x03) + 1;

				if ($y < 2 + $channelbytes)  return false;

				$channelnum = RESIP_UnpackInt(substr($data, 2, $channelbytes));
				if (!$channelnum || !isset($session->channels[$channelnum]))  return false;

				// Free up all associated resources.
				if ($session->channels[$channelnum]->fp !== false)  @fclose($session->channels[$channelnum]->fp);
				unset($session->channels[$channelnum]);

				return true;
			}
		}

		return false;
	}


	$stopfilename = __FILE__ . ".notify.stop";
	$reloadfilename = __FILE__ . ".notify.reload";
	$lastservicecheck = time();
	$running = true;

	$tracker = array();
	$tcpclients = array();
	$tcpnextclient = 1;
	$writeudppackets = array();

	do
	{
		// Implement the stream_select() call directly since multiple server instances are involved.
		$timeout = 3;
		$readfps = array();
		$writefps = array();
		$exceptfps = NULL;
		$webserver->UpdateStreamsAndTimeout("web_", $timeout, $readfps, $writefps);
		$readfps["resip_udp"] = $udpfp;
		$readfps["resip_tcp"] = $tcpfp;
		if (count($writeudppackets))  $writefps["resip_udp"] = $udpfp;
		foreach ($sessions as $session)
		{
			$clientsready = 0;
			foreach ($session->clients as $client)
			{
				// Handle TCP/IP resilient IP clients.
				if ($client->protocol === "tcp")  $readfps["resip_s_" . $session->id . "_c_" . $client->id] = $client->fp;
				if ($client->protocol === "tcp" && count($client->writedata))  $writefps["resip_s_" . $session->id . "_c_" . $client->id] = $client->fp;

				// If all clients can handle a packet from a channel, accept it.
				if (($client->protocol === "tcp" && count($client->writedata) < 2048) || ($client->protocol === "udp" && count($writeudppackets) < 20480))  $clientsready++;
			}

			// Send/Receive data to/from channel targets.
			foreach ($session->channels as $channel)
			{
				if ($channel->fp !== false)
				{
					if ($clientsready === count($session->clients))  $readfps["s_" . $session->id . "_c_" . $channel->id] = $channel->fp;

					if (count($channel->readdata))  $writefps["s_" . $session->id . "_c_" . $channel->id] = $channel->fp;
				}

				// Shorten the timeout if there are ACK packets to send on a channel that is closed.
				if (!$channel->writeopen && $channel->startread === $channel->lastread && count($channel->readack) && $clientsready === count($session->clients) && count($session->channels[0]->writepackets) < 64)
				{
					$session->nextack = 0;
					$timeout = 0;
				}

				if ($timeout > 1 && count($channel->readack))  $timeout = 1;
			}
		}
		foreach ($tcpclients as $id => $client)
		{
			// First packet must be sent by the client.  Could simply be a keep-alive packet.
			$readfps["resip_tcp_" . $id] = $client->fp;
		}
		$result = WebServer::FixedStreamSelect($readfps, $writefps, $exceptfps, $timeout);
		if ($result === false)  break;
//echo "--- Cycle (" . microtime(true) . ") ---\n";

		// Web server.
		$result = $webserver->Wait(0);

		// Handle active clients.
		foreach ($result["clients"] as $id => $client)
		{
			if (!isset($tracker[$id]))
			{
				echo "Client ID " . $id . " connected.\n";

				$tracker[$id] = array("validapikey" => false);
			}

			// Check for a valid API key.
			if (!$tracker[$id]["validapikey"] && (isset($client->headers["X-Apikey"]) || isset($client->requestvars["apikey"])))
			{
				$apikey = (isset($client->headers["X-Apikey"]) ? $client->headers["X-Apikey"] : $client->requestvars["apikey"]);

				if ($apikey === $config["apikey"])
				{
					echo "Valid API key used.\n";

					$tracker[$id]["validapikey"] = true;
				}
			}

			// Wait until the request is complete before fully processing inputs.
			if ($client->requestcomplete)
			{
				if (!$tracker[$id]["validapikey"])
				{
					echo "Missing API key.\n";

					$client->SetResponseCode(403);
					$client->SetResponseContentType("application/json");
					$client->AddResponseContent(json_encode(array("success" => false, "error" => "Invalid or missing 'apikey'.", "errorcode" => "invalid_missing_apikey")));
					$client->FinalizeResponse();
				}
				else if ($client->mode === "init_response")
				{
					echo "Sending API response for:  " . $client->request["method"] . " " . $client->url . "\n";

					// Attempt to normalize input.
					if ($client->contenthandled)  $data = $client->requestvars;
					else if (!is_object($client->readdata))  $data = @json_decode($client->readdata, true);
					else
					{
						$client->readdata->Open();
						$data = @json_decode($client->readdata->Read(1000000), true);
					}

					// Process the request.
					if (!is_array($data))  $result2 = array("success" => false, "error" => "Data sent is not an array/object or was not able to be decoded.", "errorcode" => "invalid_data");
					else
					{
						$result2 = ProcessAPI($client, $data);
						if ($result2 === false)  $webserver->RemoveClient($id);
					}

					if ($result2 !== false)
					{
						// Prevent proxies from doing bad things.
						$client->AddResponseHeader("Expires", "Tue, 03 Jul 2001 06:00:00 GMT", true);
						$client->AddResponseHeader("Last-Modified", gmdate("D, d M Y H:i:s T"), true);
						$client->AddResponseHeader("Cache-Control", "max-age=0, no-cache, must-revalidate, proxy-revalidate", true);

						if (!$result2["success"])  $client->SetResponseCode(400);

						// Send the response.
						$client->SetResponseContentType("application/json");
						$client->AddResponseContent(json_encode($result2));
						$client->FinalizeResponse();
					}
				}
			}
		}

		// Do something with removed clients.
		foreach ($result["removed"] as $id => $result2)
		{
			if (isset($tracker[$id]))
			{
				echo "Client ID " . $id . " disconnected.\n";

//				echo "Client ID " . $id . " disconnected.  Reason:\n";
//				var_dump($result2["result"]);
//				echo "\n";

				unset($tracker[$id]);
			}
		}


		// Write waiting UDP packet data.
		if (count($writeudppackets))
		{
			do
			{
				$session = $sessions[$writeudppackets[0]["sid"]];

				$channel = (isset($session->channels[$writeudppackets[0]["chid"]]) ? $session->channels[$writeudppackets[0]["chid"]] : false);
				$client = (isset($session->clients[$writeudppackets[0]["clid"]]) ? $session->clients[$writeudppackets[0]["clid"]] : false);
				$num = $writeudppackets[0]["num"];

				if ($channel === false || $client === false)
				{
echo "Ignored outgoing packet.\n";
var_dump($writeudppackets[0]);
					array_shift($writeudppackets);

					if ($channel !== false && isset($channel->writepackets[$num]))
					{
						$channel->writepackets[$num]["udp"]--;

						if (!$channel->writepackets[$num]["udp"])
						{
							if ($channel->writepackets[$num]["ack"])  $channel->writepackets[$num]["ts"] = time();
							else  unset($channel->writepackets[$num]);
						}
					}

					$sent = 1;
				}
				else
				{
echo "Sending channel " . $session->id . ":" . $channel->id . " packet " . $num . " to UDP client " . $client->addr . ".\n";
					$sent = stream_socket_sendto($udpfp, $channel->writepackets[$num]["data"], 0, $client->addr);
					if ($sent > 0)
					{
						array_shift($writeudppackets);

						if ($channel !== false && isset($channel->writepackets[$num]))
						{
							$channel->writepackets[$num]["udp"]--;

							if (!$channel->writepackets[$num]["udp"])
							{
								if ($channel->writepackets[$num]["ack"])  $channel->writepackets[$num]["ts"] = time();
								else  unset($channel->writepackets[$num]);
							}
						}
					}
				}
			} while (count($writeudppackets) && $sent > 0);
		}


		// Handle incoming UDP packets from resilient IP clients.
		$data = stream_socket_recvfrom($udpfp, MAX_UDP_PACKET, 0, $addr);

		while ($data !== false && $data !== "")
		{
			$addr = RESIP_FixUDPAddrPort($addr);

			// Decrypt and route the packet.
			$result = ExtractPacket($data);
			if ($result !== false)
			{
				// Register/update the client to receive response packets.
				$session = $result["session"];

				if (!isset($session->clients[$addr]))
				{
					$client = new stdClass();
					$client->id = $addr;
					$client->protocol = "udp";
					$client->addr = $addr;

					$session->clients[$addr] = $client;
				}

				$session->clients[$addr]->lastts = time();
			}

			$data = stream_socket_recvfrom($udpfp, MAX_UDP_PACKET, 0, $addr);
		}


		foreach ($readfps as $key => $fp)
		{
			// Handle incoming TCP packets from resilient IP clients.
			if (substr($key, 0, 8) === "resip_s_")
			{
				$pos = strpos($key, "_c_", 8);
				$sid = (int)substr($key, 8, $pos - 8);
				if (isset($sessions[$sid]))
				{
					$session = $sessions[$sid];
					$cid = substr($key, $pos + 3);
					if (isset($session->clients[$cid]))
					{
						$client = $session->clients[$cid];

						ReadRESIPTCPPackets($session, $client);
					}
				}

				unset($readfps[$key]);
			}

			// Handle first data packet from TCP/IP resilient IP clients.
			if (substr($key, 0, 10) === "resip_tcp_")
			{
				$cid = substr($key, 10);

				if (isset($tcpclients[$cid]))
				{
					$client = $tcpclients[$cid];

					ReadRESIPTCPPackets(false, $client);
				}

				unset($readfps[$key]);
			}

			// Handle incoming data from the channel.
			if (substr($key, 0, 2) === "s_")
			{
				$pos = strpos($key, "_c_", 2);
				$sid = (int)substr($key, 2, $pos - 2);
				if (isset($sessions[$sid]))
				{
					$session = $sessions[$sid];
					$cid = substr($key, $pos + 3);
					if (isset($session->channels[$cid]))
					{
						$channel = $session->channels[$cid];

						if ($channel->fp !== false)
						{
							if ($channel->protocol === "tcp")
							{
								$data = @fread($channel->fp, 65536);
echo "Read incoming:  " . $data . "\n";

								if ($data === false || ($data === "" && feof($channel->fp)))
								{
									@fclose($channel->fp);
									$channel->fp = false;

									StopChannel($session, $channel);
								}
							}
							else if ($channel->protocol === "udp")
							{
								$data = stream_socket_recvfrom($channel->fp, 65536);
							}
							else
							{
								$data = false;
							}

							if ($data !== false && $data !== "" && $channel->writeopen)
							{
								WriteChannelData($session, $channel, $data);
echo "Queued incoming data from " . $session->id . ":" . $channel->id . ".\n";
							}
						}
					}
				}

				unset($readfps[$key]);
			}
		}


		// Handle new TCP/IP resilient IP client connections.
		while (($fp = @stream_socket_accept($readfps["resip_tcp"], 0)) !== false)
		{
			// Enable non-blocking mode.
			stream_set_blocking($fp, 0);

			$client = new stdClass();
			$client->id = $tcpnextclient;
			$client->protocol = "tcp";
			$client->fp = $fp;
			$client->readdata = "";
			$client->writedata = array();
			$client->writepos = 0;
			$client->addr = stream_socket_get_name($fp, true);
			$client->lastts = time();

			$tcpclients[$tcpnextclient] = $client;

			$tcpnextclient++;
		}


		foreach ($writefps as $key => $fp)
		{
			// Handle outgoing TCP packets to resilient IP clients.
			if (substr($key, 0, 8) === "resip_s_")
			{
				$pos = strpos($key, "_c_", 8);
				$sid = (int)substr($key, 8, $pos - 8);
				if (isset($sessions[$sid]))
				{
					$session = $sessions[$sid];
					$cid = substr($key, $pos + 3);
					if (isset($session->clients[$cid]))
					{
						$client = $session->clients[$cid];

						do
						{
							$sent = @fwrite($client->fp, substr($client->writedata[0]["data"], $client->writepos));
							if ($sent === false || feof($client->fp))
							{
								@fclose($client->fp);

								unset($session->clients[$client->id]);

								$sent = 0;
							}
							else
							{
								$client->writepos += $sent;

								if ($client->writepos >= strlen($client->writedata[0]["data"]))
								{
									if (isset($session->channels[$client->writedata[0]["chid"]]))
									{
										$channel = $session->channels[$client->writedata[0]["chid"]];
										$num = $client->writedata[0]["num"];

										if (isset($channel->writepackets[$num]) && $channel->writepackets[$num]["ack"])  $channel->writepackets[$num]["ts"] = time();
									}

									array_shift($client->writedata[0]);

									$client->writepos = 0;
								}
							}
						} while ($sent > 0 && count($client->writedata));
					}
				}

				unset($writefps[$key]);
			}

			// Handle outgoing data to the channel.
			if (substr($key, 0, 2) === "s_")
			{
				$pos = strpos($key, "_c_", 2);
				$sid = (int)substr($key, 2, $pos - 2);
				if (isset($sessions[$sid]))
				{
					$session = $sessions[$sid];
					$cid = substr($key, $pos + 3);
					if (isset($session->channels[$cid]))
					{
						$channel = $session->channels[$cid];

						if ($channel->fp !== false)
						{
							if ($channel->protocol === "tcp")
							{
echo "Writing outgoing:  " . $channel->readdata[0] . "\n";
								$result2 = @fwrite($channel->fp, $channel->readdata[0]);
								if ($result2 === false || feof($channel->fp))
								{
									$channel->readdata = array();
									$channel->readopen = false;
									@fclose($channel->fp);
									$channel->fp = false;

									StopChannel($session, $channel);
								}
								else
								{
									$channel->readdata[0] = (string)substr($channel->readdata[0], $result2);
									if ($channel->readdata[0] === "")  array_shift($channel->readdata);
								}
							}
							else if ($channel->protocol === "udp")
							{
								$result2 = stream_socket_sendto($channel->fp, $channel->readdata[0], 0, $channel->fpaddr);
								if ($result2 > 0)
								{
									$client->readdata[0] = (string)substr($client->readdata[0], $result2);
									if ($client->readdata[0] === "")  array_shift($client->readdata);
								}
							}
						}
					}
				}

				unset($writefps[$key]);
			}
		}


		foreach ($sessions as $session)
		{
			// Process incoming packets.
			foreach ($session->channels as $channel)
			{
				// Is a complete data packet available?
				for ($y = $channel->startread; isset($channel->readpackets[$y]) && $channel->readpackets[$y]["fragment"]; $y++);

				if (isset($channel->readpackets[$y]) && !$channel->readpackets[$y]["fragment"])
				{
					$compressed = $channel->readpackets[$y]["compressed"];
					$y++;
					$data = "";
					for ($x = $channel->startread; $x < $y; $x++)
					{
						$data .= $channel->readpackets[$x]["data"];

						unset($channel->readpackets[$x]);
					}

					if ($channel->readopen)
					{
						// Decompress the data.
						if ($compressed)  $data = DeflateStream::Uncompress($data);

						$channel->readdata[] = $data;
					}

					$channel->startread = $y;
				}
			}

			// Process command channel packets.
			while (count($session->channels[0]->readdata))
			{
				$data = array_shift($session->channels[0]->readdata);

				ProcessCommandChannelPacket($session, $data);
			}

			while (count($session->channels[0]->readunordered))
			{
				$packet = array_shift($session->channels[0]->readunordered);

				ProcessCommandChannelPacket($session, $packet["data"]);
			}

			// Queue ACK information, resend timed out packets, and handle stopped channels.
			if ($session->nextack <= microtime(true))
			{
				$maxsize = MaxFragmentSize($session->channels[0]) - 1;
				$data = "";

				foreach ($session->channels as $channel)
				{
					$clientsready = 0;
					foreach ($session->clients as $client)
					{
						if (($client->protocol === "tcp" && count($client->writedata) < 2048) || ($client->protocol === "udp" && count($writeudppackets) < 20480))  $clientsready++;
					}

					if ($clientsready !== count($session->clients))  break;

					$channelused = false;

					if (count($session->channels[0]->writepackets) < 64)
					{
						// Queue missing packets.
						if (count($channel->readack))
						{
							// Find each range of read packets to minimize wasting space.
							$startnum = false;
							$lastnum = false;
							ksort($channel->readack);
							foreach ($channel->readack as $num => $val)
							{
								if ($startnum === false)
								{
									$startnum = $num;
									$lastnum = $num;
								}
								else if ($lastnum === $num - 1)
								{
									$lastnum = $num;
								}
								else
								{
									if (!AppendACKRange($data, $startnum, $lastnum, $channelused, $session, $channel, $maxsize))  break;

									$startnum = $num;
									$lastnum = $num;
								}
							}

							if ($startnum !== false)  AppendACKRange($data, $startnum, $lastnum, $channelused, $session, $channel, $maxsize);

							$channel->readack = array();
						}
					}

					// Resend packets when they exceed the last sent time limit.
					foreach ($channel->writepackets as $num => $packet)
					{
						if ($packet["ts"] > -1 && $packet["ts"] < time() - $packet["dist"])
						{
							$packet["ts"] = -1;
							$packet["dist"] *= 2;
							if ($packet["dist"] > 60)  $packet["dist"] = 60;
							$channel->writepackets[$num] = $packet;
echo "Re-queued " . $session->id . ":" . $channel->id . " packet " . $num . ".\n";

							// Queue for sending.
							foreach ($session->clients as $client)
							{
								if ($client->protocol === "tcp")  $client->writedata[] = array("data" => $data3, "chid" => $channel->id, "num" => $num);
								else if ($client->protocol === "udp")
								{
									$writeudppackets[] = array("sid" => $session->id, "chid" => $channel->id, "clid" => $client->id, "num" => $num);

									$channel->writepackets[$num]["udp"]++;
								}
							}
						}
					}

					// If the channel has been stopped and all packets have been received and sent, close the socket handle.
					// Client directly requests destroying a channel using the command channel.
					if ($channel->fp !== false && !$channel->writeopen && $channel->startread === $channel->lastread)
					{
echo "Closing socket for " . $session->id . ":" . $channel->id . ".\n";
						@fclose($channel->fp);
						$channel->fp = false;
					}
				}

				if ($data !== "")  WriteChannelData($session, $session->channels[0], "\x03" . $data, false);
if ($data !== "")  echo "Queued ACK packet.\n";

				$session->nextack = microtime(true) + .5;
			}

			// Remove old resilient IP clients.  They can reconnect and pick up where they left off later.
			foreach ($session->clients as $id => $client)
			{
				if ($client->lastts < time() - 60)  unset($session->clients[$id]);
			}
		}


		// Check the status of the two service file options for correct Service Manager integration.
		if ($lastservicecheck <= time() - 3)
		{
			if (file_exists($stopfilename))
			{
				// Initialize termination.
				echo "Stop requested.\n";

				$running = false;
			}
			else if (file_exists($reloadfilename))
			{
				// Reload configuration and then remove reload file.
				echo "Reload config requested.  Exiting.\n";

				$running = false;
			}

			$lastservicecheck = time();
		}
	} while ($running);
?>