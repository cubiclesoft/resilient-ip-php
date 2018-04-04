<?php
	// Resilient Internet Protocol functions
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	require_once $rootpath . "/support/random.php";

	function RESIP_LoadConfig()
	{
		global $rootpath;

		if (file_exists($rootpath . "/config.dat"))  $result = json_decode(file_get_contents($rootpath . "/config.dat"), true);
		else  $result = array();
		if (!is_array($result))  $result = array();

		return $result;
	}

	function RESIP_SaveConfig($config)
	{
		global $rootpath;

		file_put_contents($rootpath . "/config.dat", json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		@chmod($rootpath . "/config.dat", 0660);
	}

	function RESIP_FixUDPAddrPort($addr)
	{
		// Fix IPv6 addresses.  Deals with stream_socket_recvfrom() to stream_socket_sendto() issues.
		$pos = strrpos($addr, ":");
		if ($pos !== false && strpos($addr, ":") !== $pos && strpos($addr, "[") === false)  $addr = "[" . substr($addr, 0, $pos) . "]" . substr($addr, $pos);

		return $addr;
	}

	// Drop-in replacement for hash_hmac() on hosts where Hash is not available.
	// Only supports HMAC-MD5 and HMAC-SHA1.
	if (!function_exists("hash_hmac"))
	{
		function hash_hmac($algo, $data, $key, $raw_output = false)
		{
			$algo = strtolower($algo);
			$size = 64;
			$opad = str_repeat("\x5C", $size);
			$ipad = str_repeat("\x36", $size);

			if (strlen($key) > $size)  $key = $algo($key, true);
			$key = str_pad($key, $size, "\x00");

			$y = strlen($key) - 1;
			for ($x = 0; $x < $y; $x++)
			{
				$opad[$x] = $opad[$x] ^ $key[$x];
				$ipad[$x] = $ipad[$x] ^ $key[$x];
			}

			$result = $algo($opad . $algo($ipad . $data, true), $raw_output);

			return $result;
		}
	}

	class RESIP_SessionHelper
	{
		private $web, $host, $apikey, $cacert, $cert, $neterror, $serverstarted;
		private $packetsize, $maxfragments, $hashmethod, $hashsize, $rng, $cipher1, $cipher2, $cipher3, $cipher4, $sign;
		private $sessionid, $fpmode, $fp, $fphost, $lastts, $lastkeepalive, $nextack, $nextclientid, $clients, $readdata, $writedata, $writedatapos;

		public function Init($config)
		{
			global $rootpath;

			$this->web = new WebBrowser();
			$this->host = "https://" . $config["host"] . ":" . $config["session_port"];
			$this->apikey = $config["apikey"];

			// Load more classes.
			require_once $rootpath . "/support/phpseclib/Base.php";
			require_once $rootpath . "/support/phpseclib/Rijndael.php";
			require_once $rootpath . "/support/phpseclib/AES.php";

			require_once $rootpath . "/support/ipaddr.php";
			require_once $rootpath . "/support/deflate_stream.php";

			if (!DeflateStream::IsSupported())  CB_DisplayError("One or more functions are not available for data compression.  Try enabling the 'zlib' module.");

			@mkdir($rootpath . "/cache");

			$cafilename = $rootpath . "/cache/resip_ca.pem";
			$certfilename = $rootpath . "/cache/resip_cert.pem";

			$this->cacert = (file_exists($cafilename) ? file_get_contents($cafilename) : false);
			$this->cert = (file_exists($certfilename) ? file_get_contents($certfilename) : false);

			if ($this->cacert === false || $this->cert === false)
			{
				$this->cacert = false;
				$this->cert = false;

				$this->neterror = "";

				$options = array(
					"peer_cert_callback" => array($this, "Internal_PeerCertificateCheck"),
					"peer_cert_callback_opts" => "",
					"sslopts" => self::InitSSLOpts(array("verify_peer" => false, "capture_peer_cert_chain" => true))
				);

				$result = $this->web->Process($this->host . "/", $options);

				if (!$result["success"])
				{
					$result["error"] .= "  " . $this->neterror;

					CLI::DisplayError("Unable to contact remote host '" . $this->host . "'.", $result);
				}

				file_put_contents($cafilename, $this->cacert);
				file_put_contents($certfilename, $this->cert);
			}

			$this->rng = new CSPRNG();
			$this->sessionid = false;

			$this->fpmode = $config["resip_protocol"];

			if ($this->fpmode === "udp")
			{
				// Bind to a socket so that UDP response packets can be handled.
				$context = stream_context_create();
				$this->fp = stream_socket_server("udp://" . ($config["prefer_ipv6"] ? "[::0]" : "0.0.0.0") . ":0", $errornum, $errorstr, STREAM_SERVER_BIND, $context);
				if ($this->fp === false)  CLI::DisplayError("Unable to bind the local resilient IP server interface.", array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"), false);

				// Enable non-blocking mode.
				stream_set_blocking($this->fp, 0);
			}

			if (IPAddr::IsHostname($config["host"]))
			{
				$info = ($config["prefer_ipv6"] ? @dns_get_record($config["host"] . ".", DNS_AAAA) : false);
				if ($info === false || !count($info))  $info = @dns_get_record($config["host"] . ".", DNS_A);
				if ($info === false || !count($info))  $info = @dns_get_record($config["host"] . ".", DNS_ANY);

				$valid = false;

				if ($info !== false)
				{
					foreach ($info as $entry)
					{
						if ($entry["type"] === "A" || ($config["prefer_ipv6"] && $entry["type"] === "AAAA"))
						{
							$hostip = IPAddr::NormalizeIP($info[0]["ip"]);

							$valid = true;
						}
					}
				}

				if (!$valid)  CLI::DisplayError("Invalid configuration host specified.");
			}
			else
			{
				$hostip = IPAddr::NormalizeIP($config["host"]);
			}

			$this->fphost = ($config["prefer_ipv6"] ? $hostip["ipv6"] : ($hostip["ipv4"] != "" ? $hostip["ipv4"] : $hostip["ipv6"])) . ":" . $config["resip_port"];
		}

		public function GetServerInfo()
		{
			$result = $this->RunAPI("GET", "server/info");
			if (!$result["success"])  return $result;

			if ($this->serverstarted !== $result["body"]["started"])
			{
				// Session died.
				$this->sessionid = false;

				return array("success" => false, "error" => self::RESIP_Translate("Resilient IP server restarted."), "errorcode" => "resip_server_restarted");
			}

			$this->lastts = microtime(true);

			return $result["body"];
		}

		public function SessionStart($hash = "sha1")
		{
			$hash = strtolower($hash);

			$this->hashmethod = $hash;

			if ($this->hashmethod === "sha1")  $this->hashsize = 20;
			else if ($this->hashmethod === "md5")  $this->hashsize = 16;
			else  return array("success" => false, "error" => self::RESIP_Translate("Only SHA-1 and MD5 are supported HMAC methods at this time with SHA-1 preferred."), "errorcode" => "invalid_hash_method");

			$result = $this->RunAPI("POST", "session/start", array("hash" => $hash));
			if (!$result["success"])  return $result;

			if (!$result["body"]["success"])  return $result["body"];

			$this->serverstarted = $result["body"]["started"];
			$this->packetsize = $result["body"]["packet_size"];
			$this->maxfragments = $result["body"]["max_fragments"];
			if ($this->packetsize % 16 != 0 || $this->packetsize < 64)  return array("success" => false, "error" => self::RESIP_Translate("Resilient IP server returned bad packet size."), "errorcode" => "bad_packet_size");

			$this->cipher1 = new Crypt_AES();
			$this->cipher1->setKey(hex2bin($result["body"]["master"]["key1"]));
			$this->cipher1->setIV(hex2bin($result["body"]["master"]["iv1"]));
			$this->cipher1->disablePadding();
			$this->cipher2 = new Crypt_AES();
			$this->cipher2->setKey(hex2bin($result["body"]["master"]["key2"]));
			$this->cipher2->setIV(hex2bin($result["body"]["master"]["iv2"]));
			$this->cipher2->disablePadding();
			$this->cipher3 = new Crypt_AES();
			$this->cipher3->setKey(hex2bin($result["body"]["session"]["key1"]));
			$this->cipher3->setIV(hex2bin($result["body"]["session"]["iv1"]));
			$this->cipher3->disablePadding();
			$this->cipher4 = new Crypt_AES();
			$this->cipher4->setKey(hex2bin($result["body"]["session"]["key2"]));
			$this->cipher4->setIV(hex2bin($result["body"]["session"]["iv2"]));
			$this->cipher4->disablePadding();
			$this->sign = hex2bin($result["body"]["session"]["sign"]);

			$this->sessionid = $result["body"]["session_id"];
			$this->lastts = microtime(true);
			$this->lastkeepalive = 0;
			$this->nextack = microtime(true) + .5;
			$this->nextclientid = 0;
			$this->clients = array();
			$this->writedata = array();

			// Initialize the command channel.
			$this->CreateClient(false, "tcp", false, false, false);

			return $result["body"];
		}

		public function UpdateStreamsAndTimeout(&$readfps, &$writefps, &$timeout)
		{
			if ($this->fp !== false)
			{
				$readfps["main"] = $this->fp;

				if (count($this->writedata))  $writefps["main"] = $this->fp;

				foreach ($this->clients as $client)
				{
					if (!$client->writeopen && count($client->readack) && $this->CanWrite() && count($this->clients[0]->writepackets) < 64)
					{
						$this->nextack = 0;
						$timeout = 0;

						break;
					}

					if ($timeout > 1 && count($client->readack))  $timeout = 1;
				}
			}
		}

		public function CanWrite()
		{
			return (count($this->writedata) < 2048);
		}

		public function ProcessServerData()
		{
			if ($this->fpmode === "tcp" && $this->fp === false)
			{
				// Establish a connection with the remote host.  This blocks until the connection succeeds.  UDP/IP is the preferred protocol anyway.
				$context = stream_context_create();
				$this->fp = @stream_socket_client("tcp://" . $this->fphost, $errornum, $errorstr, 10, STREAM_CLIENT_CONNECT, $context);

				if ($this->fp === false)  return array("success" => true, "connected" => false, "removed" => array());

				// Enable non-blocking mode.
				stream_set_blocking($this->fp, 0);

				$this->readdata = "";
				$this->writedatapos = 0;
			}

			// Write waiting data.
			if (count($this->writedata))
			{
				do
				{
					$client = $this->clients[$this->writedata[0]["id"]];
					$num = $this->writedata[0]["num"];

					if ($this->fpmode === "udp")
					{
						// UDP mode.
echo "Sending channel " . $client->id . " packet " . $num . " to " . $this->fphost . ".\n";
						$sent = stream_socket_sendto($this->fp, $client->writepackets[$num]["data"], 0, $this->fphost);
						if ($sent > 0)
						{
							if ($client->writepackets[$num]["ack"])  $client->writepackets[$num]["ts"] = time();
							else  unset($client->writepackets[$num]);

							array_shift($this->writedata);
						}
					}
					else
					{
						// TCP mode.
						$sent = @fwrite($this->fp, substr($client->writepackets[$num]["data"], $this->writedatapos));
						if ($sent === false || feof($this->fp))
						{
							@fclose($this->fp);
							$this->fp = false;
						}
						else
						{
							$this->writedatapos += $sent;

							if (strlen($client->writepackets[$num]["data"]) <= $this->writedatapos)
							{
								if ($client->writepackets[$num]["ack"])  $client->writepackets[$num]["ts"] = time();
								else  unset($client->writepackets[$num]);

								array_shift($this->writedata);

								$this->writedatapos = 0;
							}
						}
					}
				} while (count($this->writedata) && $sent > 0);
			}

			// Read waiting data and route packets to the correct client.
			if ($this->fpmode === "udp")  $data = stream_socket_recvfrom($this->fp, $this->packetsize, 0, $addr);
			else
			{
				$data = @fread($this->fp, 65536);
				if ($data === false || ($data === "" && feof($this->fp)))
				{
					$this->fp = false;

					return array("success" => true, "connected" => false, "removed" => array());
				}

				$this->readdata .= $data;
				if (strlen($this->readdata) < $this->packetsize)  $data = false;
				else
				{
					$data = substr($this->readdata, 0, $this->packetsize);
					$this->readdata = substr($this->readdata, $this->packetsize);

					$addr = $this->fphost;
				}
			}

			while ($data !== false && $data !== "")
			{
				$addr = RESIP_FixUDPAddrPort($addr);

				if ($addr === $this->fphost)
				{
					$client = $this->ExtractPacket($data);
					if ($client !== false)
					{
						// Is a complete data packet available?
						for ($y = $client->startread; isset($client->readpackets[$y]) && $client->readpackets[$y]["fragment"]; $y++);

						if (isset($client->readpackets[$y]) && !$client->readpackets[$y]["fragment"])
						{
							$compressed = $client->readpackets[$y]["compressed"];
							$y++;
							$data = "";
							for ($x = $client->startread; $x < $y; $x++)
							{
								$data .= $client->readpackets[$x]["data"];

								unset($client->readpackets[$x]);
							}

							if ($client->readopen)
							{
								// Decompress the data.
								if ($compressed)  $data = DeflateStream::Uncompress($data);

								$client->readdata[] = $data;
							}

							$client->startread = $y;
						}
					}

					$this->lastts = microtime(true);
				}

				if ($this->fpmode === "udp")  $data = stream_socket_recvfrom($this->fp, $this->packetsize, 0, $addr);
				else
				{
					if (strlen($this->readdata) < $this->packetsize)
					{
						$data = @fread($this->fp, 65536);
						if ($data === false || ($data === "" && feof($this->fp)))
						{
							$this->fp = false;

							return array("success" => true, "connected" => false, "removed" => array());
						}

						$this->readdata .= $data;
					}

					if (strlen($this->readdata) < $this->packetsize)  $data = false;
					else
					{
						$data = substr($this->readdata, 0, $this->packetsize);
						$this->readdata = substr($this->readdata, $this->packetsize);

						$addr = $this->fphost;
					}
				}
			}

			// Process command channel packets.
			while (count($this->clients[0]->readdata))
			{
				$data = array_shift($this->clients[0]->readdata);

				$this->ProcessCommandChannelPacket($data);
			}

			while (count($this->clients[0]->readunordered))
			{
				$packet = array_shift($this->clients[0]->readunordered);

				$this->ProcessCommandChannelPacket($packet["data"]);
			}

			// Queue ACK information, resend timed out packets, and handle stopped channels.
			$removed = array();
			if ($this->nextack <= microtime(true))
			{
				$maxsize = $this->MaxFragmentSize($this->clients[0]) - 1;
				$data = "";

				foreach ($this->clients as $client)
				{
					if (!$this->CanWrite())  break;

					$clientused = false;

					if (count($this->clients[0]->writepackets) < 64)
					{
						// Queue missing packets.
						if (count($client->readack))
						{
							// Find each range of read packets to minimize wasting space.
							$startnum = false;
							$lastnum = false;
							ksort($client->readack);
							foreach ($client->readack as $num => $val)
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
									if (!$this->AppendACKRange($data, $startnum, $lastnum, $clientused, $client, $maxsize))  break;

									$startnum = $num;
									$lastnum = $num;
								}
							}

							if ($startnum !== false)  $this->AppendACKRange($data, $startnum, $lastnum, $clientused, $client, $maxsize);

							$client->readack = array();
						}
					}

					// Resend packets when they exceed the last sent time limit.
					foreach ($client->writepackets as $num => $packet)
					{
						if ($packet["ts"] > -1 && $packet["ts"] < time() - $packet["dist"])
						{
							$packet["ts"] = -1;
							$packet["dist"] *= 2;
							if ($packet["dist"] > 60)  $packet["dist"] = 60;
							$client->writepackets[$num] = $packet;
echo "Re-queued channel " . $client->id . " packet " . $num . ".\n";

							$this->writedata[] = array("id" => $client->id, "num" => $num);
						}
					}
				}

				if ($data !== "")  $this->WriteChannelData($this->clients[0], "\x03" . $data, false);
if ($data !== "")  echo "Queued ACK packet.\n";

				$this->nextack = microtime(true) + .5;
			}

			// If a channel has been stopped and all packets have been sent and received, remove the client.
			foreach ($this->clients as $client)
			{
				if (!$client->writeopen && $client->startread === $client->lastread && !count($client->readdata) && !count($client->readpackets) && !count($client->writepackets))
				{
					// Command channel (0) first byte:  3 bits reserved, 5 bits command.
					// Terminate channel command (5).
					$data2 = "\x05";

					// Next byte:  6 bits reserved, 2 bits channel size.
					$data .= chr(self::GetBitsIntSize($client->id));

					// Channel.
					$data .= self::PackInt($client->id);

					$this->WriteChannelData($this->clients[0], $data2);
echo "Queued channel termination packet.\n";

					$removed[$client->id] = $client;
					unset($this->clients[$client->id]);
echo "Removed channel " . $client->id . ".\n";
				}
			}

			// Queue a keep alive packet.  This is more efficient than using the API to confirm that the session is still valid.
			// Server restarts, router table issues, IP address changes, and other possible Internet/network conditions make this necessary.
			if ($this->lastts < time() - 60 && $this->lastkeepalive < time() - (count($this->clients) > 1 ? 15 : 250))
			{
				// Command channel (0) first byte:  3 bits reserved, 5 bits command.
				// Keep alive channel command (4).
				$this->WriteChannelData($this->clients[0], "\x04", false);
echo "Queued keep-alive packet.\n";

				$this->lastkeepalive = microtime(true);
			}

			return array("success" => true, "connected" => ($this->fp !== false && (count($this->clients) == 1 || $this->lastts > time() - 300)), "removed" => $removed);
		}

		private function AppendACKRange(&$data, $startnum, $lastnum, &$clientused, $client, $maxsize)
		{
			// Info byte:  1 bit (1), 1 bit range, 3 bits packet number size, 3 bits packet number size (unused when 'range' is 0).
			$data2 = chr(0x80 | ($startnum !== $lastnum ? 0x40 : 0x00) | (self::GetBitsIntSize($startnum) << 3) | ($startnum !== $lastnum ? self::GetBitsIntSize($lastnum) : 0x00));

			// Start packet number.
			$data2 .= self::PackInt($startnum);

			// Last packet number.
			if ($startnum !== $lastnum)  $data2 .= self::PackInt($lastnum);

			if (!$clientused)
			{
				// Next byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
				$data3 = chr(self::GetBitsIntSize($client->id));

				// Channel.
				$data3 .= self::PackInt($client->id);

				$data2 = $data3 . $data2;

				$clientused = true;
			}

			if (strlen($data) + strlen($data2) > $maxsize)
			{
				// Write out the packet and reset for a new packet.
				// Command channel (0) first byte:  3 bits reserved, 5 bits command.
				// ACK channel command (3).
				$this->WriteChannelData($this->clients[0], "\x03" . $data, false);
echo "Queued ACK packet.\n";

				$data = "";

				if (count($this->clients[0]->writepackets) >= 64)  return false;

				// Next byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
				$data3 .= chr(self::GetBitsIntSize($client->id));

				// Channel.
				$data3 .= self::PackInt($client->id);

				$data2 = $data3 . $data2;
			}

			$data .= $data2;

			return true;
		}

		private function ProcessCommandChannelPacket($data)
		{
			$y = strlen($data);
			if ($y < 1)  return false;

			// Extract the command.
			$command = ord($data{0}) & 0x1F;
echo "Received command:  " . $command . "\n";

			switch ($command)
			{
				case 1:
				{
					// Connection successfully initalized.
					// Since this is an async/non-blocking operation, it may still fail to connect
					// BUT the server side structures exist and can start receiving data now.
					if ($y < 2)  return false;

					// Next byte:  6 bits reserved, 2 bits channel size.
					$tempbyte = ord($data{1});
					$channelbytes = ($tempbyte & 0x03) + 1;

					if ($y < 2 + $channelbytes)  return false;

					$channel = self::UnpackInt(substr($data, 2, $channelbytes));
					if (!$channel || !isset($this->clients[$channel]))  return false;
					$client = $this->clients[$channel];

					$client->established = true;

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

					$channel = self::UnpackInt(substr($data, 2, $channelbytes));
					if (!$channel || !isset($this->clients[$channel]))  return false;
					$client = $this->clients[$channel];
					$x = 2 + $channelbytes;

					$client->lastread = self::UnpackInt(substr($data, $x, $packetnumbytes)) + 1;

					$this->StopChannel($client);

					return true;
				}
				case 3:
				{
					// ACK.
					if ($y < 2)  return false;

					$x = 1;
					$channel = false;
					$client = false;
					while ($x < $y)
					{
						// First bit differentiates whether the current byte is a channel byte or an information byte.
						$tempbyte = ord($data{$x});
						$x++;

						if ($tempbyte & 0x80)
						{
							// Info byte:  1 bit (1), 1 bit range, 3 bits packet number size, 3 bits packet number size (unused when 'range' is 0).
							if ($channel === false)  return false;
							$range = (($tempbyte & 0x40) !== 0);
							$startnumbytes = (($tempbyte >> 3) & 0x07) + 1;
							$lastnumbytes = ($range ? ($tempbyte & 0x07) + 1 : 0);
							if ($y < $x + $startnumbytes + $lastnumbytes)  return false;

							$startnum = self::UnpackInt(substr($data, $x, $startnumbytes));
							$x += $startnumbytes;

							$lastnum = ($range ? self::UnpackInt(substr($data, $x, $lastnumbytes)) : $startnum);
							$x += $lastnumbytes;

							if ($client !== false)
							{
								for (; $startnum <= $lastnum; $startnum++)
								{
									unset($client->writepackets[$startnum]);
								}
							}
						}
						else
						{
							// Channel byte:  1 bit (0), 5 bits reserved, 2 bits channel size.
							$channelbytes = ($tempbyte & 0x03) + 1;

							if ($y < $x + $channelbytes)  return false;

							$channel = self::UnpackInt(substr($data, $x, $channelbytes));
							$x += $channelbytes;
							$client = (isset($this->clients[$channel]) ? $this->clients[$channel] : false);
						}
					}

					return true;
				}
				case 4:
				{
					// Keep-alive response packet received.

					return true;
				}
			}

			return false;
		}

		private function ExtractPacket($data)
		{
echo "---- Received Packet (" . microtime(true) . ") ----\n";
			if (strlen($data) !== $this->packetsize)  return false;

			// Unwrap the session encrypted data block.
			// Decrypt the block.
			$data = $this->cipher2->decrypt($data);

			// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
			$data = substr($data, 1) . substr($data, 0, 1);

			// Decrypt the block again.
			$data = $this->cipher1->decrypt($data);

			// Handle packet type.
			$tempbyte = ord($data{1});
			$packettype = ($tempbyte & 0x0F);
echo "  Packet type:  " . $packettype . "\n";
			if ($packettype !== 0)  return false;

			// Verify session ID.
			$sessionid = self::UnpackInt(substr($data, 2, 4));
echo "  Session ID:  " . $sessionid . "\n";
			if ($sessionid !== $this->sessionid)  return false;

			// Verify the hash.
			$hash = substr($data, -$this->hashsize);
			$data = substr($data, 6, $this->packetsize - 32);
			if (hash_hmac($this->hashmethod, $data, $this->sign, true) !== $hash)  return false;


			// Extract the session data.
			// Decrypt the block.
			$data = $this->cipher4->decrypt($data);

			// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
			$data = substr($data, 1) . substr($data, 0, 1);

			// Decrypt the block again.
			$data = $this->cipher3->decrypt($data);

			// Verify server bit.
			$tempbyte = ord($data{1});
			if (($tempbyte & 0x80) === 0)  return false;

			// Extract compression, fragmentation, and size details.
			$compressed = (($tempbyte & 0x40) !== 0);
			$fragment = (($tempbyte & 0x20) !== 0);
			$channelbytes = (($tempbyte >> 3) & 0x03) + 1;
			$packetnumbytes = ($tempbyte & 0x07) + 1;

			// Extract channel, packet number, and data size.
			$channel = self::UnpackInt(substr($data, 2, $channelbytes));
echo "  Channel:  " . $channel . "\n";
			if ($channel === 0 && $fragment)  return false;
			if (!isset($this->clients[$channel]))  return false;
			$client = $this->clients[$channel];
			if ($compressed && !$client->compress)  return false;
			$x = 2 + $channelbytes;

			// Ignore packets that have already been received and/or processed.
			$packetnum = self::UnpackInt(substr($data, $x, $packetnumbytes));
echo "  Packet number:  " . $packetnum . "\n";
			if (!$packetnum && ($channel || $fragment))  return false;
			if ($packetnum > 0 && ($packetnum < $client->startread || isset($client->readpackets[$packetnum])))
			{
				$client->readack[$packetnum] = true;

				return false;
			}
			if ($client->lastread !== false && $packetnum > $client->lastread)  return false;
			$x += $packetnumbytes;

			$datasize = self::UnpackInt(substr($data, $x, 2));
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

			$client->lastts = microtime(true);
			if (!$packetnum)  $client->readunordered[] = $packet;
			else
			{
				$client->readpackets[$packetnum] = $packet;

				// Register to send an acknowledgement packet.  This is somewhat spurious for TCP/IP resilient IP server connections
				// but it does help pick up where the packets ended during reestablishment of a lost connection.
				$client->readack[$packetnum] = true;

				if ($client->nextread <= $packetnum)  $client->nextread = $packetnum + 1;
			}

			return $client;
		}

		public function MaxFragmentSize($client)
		{
			return $this->packetsize - 32 - 5 - self::GetBitsIntSize($client->id) - self::GetBitsIntSize($client->nextwrite);
		}

		public function WriteChannelData($client, $data, $ack = true)
		{
			$maxsize = $this->MaxFragmentSize($client);
			$chunks = str_split($data, $maxsize * $this->maxfragments);

			foreach ($chunks as $data)
			{
				// Compress the data at once.
				if ($client->compress)  $data = DeflateStream::Compress($data);

				// Split the data into fragments.
				$maxsize = $this->MaxFragmentSize($client);
				$x = 0;
				$y = strlen($data);
				while ($x < $y)
				{
					$size = ($x + $maxsize < $y ? $maxsize : $y - $x);

					// Build the session encrypted data block.
					// Random byte for a block offset.
					$data2 = $this->rng->GetBytes(1);

					// 1 bit client (0), 1 bit compressed, 1 bit message continued (fragmented data), 2 bits channel size, 3 bits packet number size.
					$data2 .= chr(($client->compress ? 0x40 : 0x00) | ($x + $size < $y ? 0x20 : 0x00) | (self::GetBitsIntSize($client->id) << 3) | self::GetBitsIntSize($ack ? $client->nextwrite : 0));

					// Channel.
					$data2 .= self::PackInt($client->id);

					// Packet number.
					$data2 .= self::PackInt($ack ? $client->nextwrite : 0);

					// Packet data size.
					$data2 .= pack("n", $size);

					// Packet data.
					$data2 .= substr($data, $x, $size);

					// Pad out to max size.
					$data2 .= $this->rng->GetBytes($this->packetsize - 32 - strlen($data2));

					// Encrypt the block.
					$data2 = $this->cipher3->encrypt($data2);

					// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
					$data2 = substr($data2, -1) . substr($data2, 0, -1);

					// Encrypt the block again.
					$data2 = $this->cipher4->encrypt($data2);


					// Wrap the session encrypted data block.
					// Random byte for a block offset.
					$data3 = $this->rng->GetBytes(1);

					// 4 bits reserved, 4 bits packet type (0).
					$data3 .= "\x00";

					// Session ID.
					$data3 .= pack("N", $this->sessionid);

					// Session encrypted data.
					$data3 .= $data2;

					// Add random bytes based on a fixed data size.
					$data3 .= $this->rng->GetBytes(32 - $this->hashsize - 6);

					// Sign the encrypted data packet.
					$data3 .= hash_hmac($this->hashmethod, $data2, $this->sign, true);

					// Encrypt the block.
					$data3 = $this->cipher1->encrypt($data3);

					// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
					$data3 = substr($data3, -1) . substr($data3, 0, -1);

					// Encrypt the block again.
					$data3 = $this->cipher2->encrypt($data3);


					// Append to client write queue for resending.
					if ($ack)
					{
						$writenum = $client->nextwrite;
						$client->nextwrite++;
					}
					else
					{
						$writenum = $client->unorderedwrite;
						$client->unorderedwrite--;
					}
					$client->writepackets[$writenum] = array("data" => $data3, "ack" => $ack, "ts" => -1, "dist" => 3);

					// Queue for sending.
					$this->writedata[] = array("id" => $client->id, "num" => $writenum);

					$x += $size;
				}
			}
		}

		public function StartChannel($client, $protocol, $remoteip, $remoteport)
		{
			if ($remoteport < 1 || $remoteport > 65535)  return false;

			// Command channel (0) first byte:  3 bits reserved, 5 bits command.
			// Start channel command (1).
			$data = "\x01";

			// Next byte:  1 bit compression support, 1 bit fragmentation support (1), 2 bits channel size, 2 bits IP version (0 = IPv4, 1 = IPv6), 2 bits port number size.
			$data .= chr(($client->compress ? 0x80 : 0x00) | 0x40 | (self::GetBitsIntSize($client->id) << 4) | ($remoteip["ipv4"] !== "" ? 0x00 : 0x10) | self::GetBitsIntSize($remoteport));

			// Channel.
			$data .= self::PackInt($client->id);

			// Protocol number.
			// TCP is 6 (0x06), UDP is 17 (0x11), ICMP is 1 (0x01).
			if ($protocol === "tcp")  $data .= "\x06";
			else if ($protocol === "udp")  $data .= "\x11";
			else if ($protocol === "icmp")  $data .= "\x01";
			else  $data .= "\x00";

			// IP address.
			if ($remoteip["ipv4"] !== "")
			{
				$nums = explode(".", $remoteip["ipv4"]);
				foreach ($nums as $num)  $data .= chr((int)$num);
			}
			else
			{
				$str = str_replace(":", "", $remoteip["ipv6"]);
				$data .= hex2bin($str);
			}

			// Port number.
			$data .= self::PackInt($remoteport);

			$this->WriteChannelData($this->clients[0], $data);
echo "Queued start channel packet for channel " . $client->id . ".\n";

			return true;
		}

		public function StopChannel($client)
		{
			// Don't allow the command channel to be stopped and ignore duplicate stop requests.
			if (!$client->id || !$client->writeopen)  return false;

			// Command channel (0) first byte:  3 bits reserved, 5 bits command.
			// Stop channel command (2).
			$data = "\x02";

			// Next byte:  3 bits reserved, 2 bits channel size, 3 bits last packet size.
			$data .= chr((self::GetBitsIntSize($client->id) << 3) | self::GetBitsIntSize($client->nextwrite - 1));

			// Channel.
			$data .= self::PackInt($client->id);

			// Last packet number.
			$data .= self::PackInt($client->nextwrite - 1);

			$this->WriteChannelData($this->clients[0], $data);
echo "Queued stop channel packet for channel " . $client->id . ".\n";

			$client->writeopen = false;

			return true;
		}

		public function CreateClient($compress, $protocol, $remoteip, $remoteport)
		{
			$client = new stdClass();

			$client->id = $this->nextclientid;
			$client->established = (!$this->nextclientid);
			$client->readdata = array();
			$client->lastts = microtime(true);
			$client->compress = $compress;
			$client->readopen = true;
			$client->readpackets = array();
			if (!$this->nextclientid)  $client->readunordered = array();
			$client->readack = array();
			$client->startread = 1;  // Starting number for reading packets.
			$client->nextread = 1;  // Expected next packet number.
			$client->lastread = false;
			$client->writeopen = true;
			$client->writepackets = array();
			$client->nextwrite = 1;  // Next packet number to write.
			if (!$this->nextclientid)  $client->unorderedwrite = -1;  // Unordered packet number to write.

			$this->StartChannel($client, $protocol, $remoteip, $remoteport);

			$this->nextclientid++;

			$this->clients[$client->id] = $client;

			return $client;
		}

		// Internal function to retrieve a X509 SSL certificate during the initial connection to confirm that this is the correct target server.
		public function Internal_PeerCertificateCheck($type, $cert, $opts)
		{
			if (is_array($cert))
			{
				// The server is incorrectly configured if it doesn't have the self-signed root certificate in the chain.
				if (count($cert) < 2)
				{
					$this->neterror = "Certificate chain is missing the root certificate.  Remote host is incorrectly configured.";

					return false;
				}

				// The last entry is the root cert.
				if (!openssl_x509_export($cert[count($cert) - 1], $str))
				{
					$this->neterror = "Certificate chain contains an invalid root certificate.  Corrupted on remote host?";

					return false;
				}

				$this->cacert = $str;
			}
			else
			{
				if (!openssl_x509_export($cert, $str))
				{
					$this->neterror = "Server certificate is invalid.  Corrupted on remote host?";

					return false;
				}

				// Initial setup automatically trusts the SSL/TLS certificate of the host.
				if ($this->cert === false)  $this->cert = $str;
				else if ($str !== $this->cert)
				{
					$this->neterror = "Certificate does not exactly match local certificate.  Your client is either under a MITM attack or the remote host changed certificates.";

					return false;
				}
			}

			return true;
		}

		private static function InitSSLOpts($options)
		{
			$result = array_merge(array(
				"ciphers" => "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS",
				"disable_compression" => true,
				"allow_self_signed" => false,
				"verify_peer_name" => false,
				"verify_depth" => 3,
				"capture_peer_cert" => true,
			), $options);

			return $result;
		}

		private static function RESIP_Translate()
		{
			$args = func_get_args();
			if (!count($args))  return "";

			return call_user_func_array((defined("CS_TRANSLATE_FUNC") && function_exists(CS_TRANSLATE_FUNC) ? CS_TRANSLATE_FUNC : "sprintf"), $args);
		}

		private function RunAPI($method, $apipath, $options = array(), $expected = 200, $encodejson = true, $decodebody = true)
		{
			global $rootpath;

			$cafilename = $rootpath . "/cache/resip_ca.pem";

			if ($this->host === false || $this->apikey === false)  return array("success" => false, "error" => self::RESIP_Translate("Missing host or API key."), "errorcode" => "no_access_info");
			if (!file_exists($cafilename) || $this->cert === false)  return array("success" => false, "error" => self::RESIP_Translate("Missing SSL Certificate or Certificate Authority filename."), "errorcode" => "critical_ssl_info_missing");

			$options2 = array(
				"method" => $method,
				"headers" => array(
					"X-APIKey" => $this->apikey
				),
				"peer_cert_callback" => array($this, "Internal_PeerCertificateCheck"),
				"peer_cert_callback_opts" => "",
				"sslopts" => self::InitSSLOpts(array("cafile" => $cafilename, "verify_peer" => true))
			);

			if ($encodejson && $method !== "GET")
			{
				$options2["headers"]["Content-Type"] = "application/json";
				$options2["body"] = json_encode($options);
			}
			else
			{
				$options2 = array_merge($options2, $options);
			}

			$result = $this->web->Process($this->host . "/resip/v1/" . $apipath, $options2);
			if (!$result["success"])  return $result;

			// The Session server always responds with 400 Bad Request for errors.  Attempt to decode the error.
			if ($result["response"]["code"] == 400)
			{
				$error = @json_decode($result["body"], true);
				if (is_array($error) && isset($error["success"]) && !$error["success"])  return $error;
			}

			if ($result["response"]["code"] != $expected)  return array("success" => false, "error" => self::RESIP_Translate("Expected a %d response from the Session server.  Received '%s'.", $expected, $result["response"]["line"]), "errorcode" => "unexpected_session_server_response", "info" => $result);

			if ($decodebody)  $result["body"] = json_decode($result["body"], true);

			return $result;
		}


		public static function GetBitsIntSize($val)
		{
			if ($val < 256)  return 0;
			if ($val < 65536)  return 1;
			if ($val < 16777216)  return 2;
			if ($val < 4294967296)  return 3;
			if ($val < 1099511627776)  return 4;
			if ($val < 281474976710656)  return 5;
			if ($val < 72057594037927936)  return 6;

			return 7;
		}

		public static function PackInt($num)
		{
			if ($num === 0)  return "\x00";

			$result = "";

			if (is_int(2147483648))  $floatlim = 9223372036854775808;
			else  $floatlim = 2147483648;

			if (is_float($num))
			{
				$num = floor($num);
				if ($num < (double)$floatlim)  $num = (int)$num;
			}

			while (is_float($num))
			{
				$byte = (int)fmod($num, 256);
				$result = chr($byte) . $result;

				$num = floor($num / 256);
				if (is_float($num) && $num < (double)$floatlim)  $num = (int)$num;
			}

			while ($num > 0)
			{
				$byte = $num & 0xFF;
				$result = chr($byte) . $result;
				$num = $num >> 8;
			}

			$result = substr($result, -8);

			return $result;
		}

		public static function UnpackInt($data)
		{
			if ($data === false)  return false;

			$result = 0;
			$y = strlen($data);
			for ($x = 0; $x < $y; $x++)
			{
				$result = ($result * 256) + ord($data{$x});
			}

			return $result;
		}
	}

	// Check enabled extensions.
	if (!extension_loaded("openssl"))  CB_DisplayError("The 'openssl' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");
	if (!extension_loaded("zlib"))  CB_DisplayError("The 'zlib' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");
?>