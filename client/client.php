<?php
	// Resilient IP client.
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
	require_once $rootpath . "/support/web_browser.php";
	require_once $rootpath . "/support/web_server.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"?" => "help"
		),
		"rules" => array(
			"protocol" => array("arg" => true, "multiple" => true),
			"remote_host" => array("arg" => true, "multiple" => true),
			"remote_port" => array("arg" => true, "multiple" => true),
			"compress" => array("arg" => true, "multiple" => true),
			"local_ipv6" => array("arg" => true, "multiple" => true),
			"local_port" => array("arg" => true, "multiple" => true),
			"more" => array("arg" => true, "multiple" => true),
			"help" => array("arg" => false)
		)
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "Resilient IP client\n";
		echo "Purpose:  Runs the resilient IP client.\n";
		echo "\n";
		echo "This tool is question/answer enabled.  Just running it will provide a guided interface.  It can also be run entirely from the command-line if you know all the answers.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options]\n";
		echo "\n";
		echo "Example:\n";
		echo "\tphp " . $args["file"] . "\n";

		exit();
	}

	$config = RESIP_LoadConfig();

	if (!isset($config["resip_port"]))  CLI::DisplayError("Configuration is incomplete or missing.  Run 'install.php' first.");

	$sessionhelper = new RESIP_SessionHelper();
	$sessionhelper->Init($config);


	// Get a sequence of local to remote mappings from the user.
	$servers = array();
	do
	{
		$protocols = array(
// Options for a future release.
//			"socks" => "SOCKS5 proxy",
//			"http" => "HTTP proxy",
			"tcp" => "TCP/IP tunnel",
			"udp" => "UDP/IP tunnel"
		);

		$protocol = CLI::GetLimitedUserInputWithArgs($args, "protocol", "Protocol", "tcp", "Available forwarding protocols:", $protocols, true);

		do
		{
			$remotehost = CLI::GetUserInputWithArgs($args, "remote_host", "Remote host", false, "The remote host is the final target host you want to send packets to via the resilient IP server.");

			if (IPAddr::IsHostname($remotehost))
			{
				$info = ($config["prefer_ipv6"] ? @dns_get_record($remotehost . ".", DNS_AAAA) : false);
				if ($info === false || !count($info))  $info = @dns_get_record($remotehost . ".", DNS_A);
				if ($info === false || !count($info))  $info = @dns_get_record($remotehost . ".", DNS_ANY);

				$valid = false;

				if ($info !== false)
				{
					foreach ($info as $entry)
					{
						if ($entry["type"] === "A" || ($config["prefer_ipv6"] && $entry["type"] === "AAAA"))
						{
							$remoteip = IPAddr::NormalizeIP($info[0]["ip"]);

							$valid = true;

							break;
						}
					}
				}

				if (!$valid)  CLI::DisplayError("Invalid remote host specified.  Try again.", false, false);
			}
			else
			{
				$remoteip = IPAddr::NormalizeIP($remotehost);

				$valid = true;
			}
		} while (!$valid);

		do
		{
			$port = (int)CLI::GetUserInputWithArgs($args, "remote_port", "Remote port", false, "The remote port is a port on the final target host you want to send packets to via the resilient IP server.");
			if ($port < 1 || $port > 65535)  CLI::DisplayError("Invalid port number specified.  Try again.", false, false);
		} while ($port < 1 || $port > 65535);
		$remoteport = $port;

		$compress = CLI::GetYesNoUserInputWithArgs($args, "compress", "Compress data", "N");

		do
		{
			$ipv6 = CLI::GetYesNoUserInputWithArgs($args, "local_ipv6", "Localhost IPv6", "N");
			$localhost = ($ipv6 ? "[::1]" : "127.0.0.1");

			$port = (int)CLI::GetUserInputWithArgs($args, "local_port", "Localhost port", false, "The localhost port is a port on this computer you will point another piece of software at.  The client (this program) will then route packets to the target remote host and port via the resilient IP server.");
			$valid = false;
			if ($port < 1 || $port > 65535)  CLI::DisplayError("Invalid port number specified.  Try again.", false, false);
			else
			{
				// Attempt to set up the server.
				$context = stream_context_create();

				$fp = stream_socket_server($protocol . "://" . $localhost . ":" . $port, $errornum, $errorstr, ($protocol === "tcp" ? STREAM_SERVER_BIND | STREAM_SERVER_LISTEN : STREAM_SERVER_BIND), $context);
				if ($fp === false)  CLI::DisplayError("Unable to start the localhost server on port " . $port . ".", array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"), false);
				else
				{
					// Enable non-blocking mode.
					stream_set_blocking($fp, 0);

					$servers[] = array(
						"fp" => $fp,
						"compress" => $compress,
						"protocol" => $protocol,
						"remoteip" => $remoteip,
						"remoteport" => $remoteport,
						"ipv6" => $ipv6,
						"localport" => $port
					);

					$valid = true;
				}
			}
		} while (!$valid);

		$more = CLI::GetYesNoUserInputWithArgs($args, "more", "Add another tunnel", "N");

	} while ($more);

	$currstate = "init_session";
	$lastpacketts = time();
	$expectpacket = false;
	$tracker = array();
	$udpmap = array();

	$stopfilename = __FILE__ . ".notify.stop";
	$reloadfilename = __FILE__ . ".notify.reload";
	$lastservicecheck = time();
	$running = true;

	do
	{
		switch ($currstate)
		{
			case "init_session":
			{
				// Initialize a new resilient IP server session.
				$result = $sessionhelper->SessionStart();
				if ($result["success"])  $currstate = "main";
				else
				{
					CLI::DisplayError("Unable to start resilient IP session.", $result, false);

					sleep(15);
				}

				break;
			}
			case "verify_session":
			{
				// Session verification is only performed if no packets have been received for a while.
				// The start time of the server dictates whether the master encryption keys are valid or not.
				$result = $sessionhelper->GetServerInfo();
				if ($result["success"])
				{
					$lastpacketts = time();

					$currstate = "main";
				}
				else if ($result["errorcode"] === "resip_server_restarted")
				{
					CLI::DisplayError("Resilient IP session reset.", $result, false);

					// Reset client.
					$lastpacketts = time();
					$expectpacket = false;
					$tracker = array();

					$currstate = "init_session";
				}
				else
				{
					CLI::DisplayError("Unable to verify resilient IP session.  Session server possibly down.", $result, false);

					sleep(15);
				}

				break;
			}
			case "main":
			{
				// Implement the stream_select() call directly since multiple server instances are involved.
				$timeout = 3;
				$readfps = array();
				$writefps = array();
				$exceptfps = NULL;
				$sessionhelper->UpdateStreamsAndTimeout($readfps, $writefps, $timeout);
				foreach ($servers as $num => $info)
				{
					// Accept new TCP/IP connections or UDP data if UDP data can be written to the remote end of the tunnel.
					if ($info["protocol"] === "tcp" || $sessionhelper->CanWrite())  $readfps["s_" . $num] = $info["fp"];
				}
				foreach ($tracker as $id => $info)
				{
					// Register the TCP client or UDP server for writing if there is data to send to the local end of the tunnel.
					if (count($info["client"]->readdata))  $writefps[($info["protocol"] === "tcp" ? "c_" . $id : "s_" . $info["servernum"])] = $info["fp"];

					// Register the client for reading if TCP data can be written to the remote end of the tunnel.
					if ($info["protocol"] === "tcp" && $info["client"]->established && $info["client"]->writeopen && $sessionhelper->CanWrite())  $readfps["c_" . $id] = $info["fp"];
				}

				$result = WebServer::FixedStreamSelect($readfps, $writefps, $exceptfps, $timeout);
				if ($result === false)  break;
//echo "--- Cycle (" . microtime(true) . ") ---\n";

				// Process incoming connections and re-route incoming localhost UDP server data to the correct channel.
				foreach ($readfps as $key => $val)
				{
					if (substr($key, 0, 2) === "s_")
					{
						$num = (int)substr($key, 2);

						if ($servers[$num]["protocol"] === "tcp")
						{
							while (($fp = @stream_socket_accept($servers[$num]["fp"], 0)) !== false)
							{
								// Enable non-blocking mode.
								stream_set_blocking($fp, 0);

								$client = $sessionhelper->CreateClient($servers[$num]["compress"], $servers[$num]["protocol"], $servers[$num]["remoteip"], $servers[$num]["remoteport"]);

								$tracker[$client->id] = array(
									"protocol" => "tcp",
									"fp" => $fp,
									"ipaddr" => stream_socket_get_name($fp, true),
									"client" => $client
								);
							}
						}
						else if ($servers[$num]["protocol"] === "udp")
						{
							if ($sessionhelper->CanWrite())
							{
								$data = stream_socket_recvfrom($servers[$num]["fp"], 65536, 0, $addr);

								while ($data !== false && $data !== "")
								{
									$addr = RESIP_FixUDPAddrPort($addr);

									// Process the address.  If it doesn't map to an open client (channel), then create it.
									if (!isset($udpmap[$addr]))
									{
										$client = $sessionhelper->CreateClient($servers[$num]["compress"], $servers[$num]["protocol"], $server[$num]["remoteip"], $server[$num]["remoteport"]);

										$tracker[$client->id] = array(
											"protocol" => "udp",
											"servernum" => $num,
											"fp" => $servers[$num]["fp"],
											"ts" => 0,
											"ipaddr" => $addr,
											"client" => $client
										);

										$udpmap[$addr] = $client->id;
									}

									// Route the packet to the client.
									$id = $udpmap[$addr];
									$client = $tracker[$id]["client"];
									$tracker[$id]["ts"] = time();
									if ($client->writeopen)
									{
										$sessionhelper->WriteChannelData($client, $data);
echo "Queued UDP data for channel " . $client->id . ".\n";
									}

									if ($sessionhelper->CanWrite())  $data = stream_socket_recvfrom($servers[$num]["fp"], 65536, 0, $addr);
									else  $data = false;
								}
							}
						}

						unset($readfps[$key]);
					}
				}

				// Process incoming TCP data.
				foreach ($readfps as $key => $val)
				{
					if (substr($key, 0, 2) === "c_")
					{
						$id = (int)substr($key, 2);
						$info = $tracker[$id];

						if ($info["protocol"] === "tcp")
						{
							$data = @fread($info["fp"], 65536);

							if ($data === false || ($data === "" && feof($info["fp"])))  $sessionhelper->StopChannel($info["client"]);
							else
							{
								$sessionhelper->WriteChannelData($info["client"], $data);
echo "Queued TCP data for channel " . $info["client"]->id . ".\n";
							}
						}
					}
				}

				// Send outgoing data back to the localhost connected application.
				foreach ($tracker as $id => $info)
				{
					$client = $info["client"];

					if (count($client->readdata))
					{
						$key = ($info["protocol"] === "tcp" ? "c_" . $id : "s_" . $info["servernum"]);

						if (isset($writefps[$key]))
						{
							if ($info["protocol"] === "tcp")
							{
								$result2 = @fwrite($info["fp"], $client->readdata[0]);
								if ($result2 === false || feof($info["fp"]))
								{
									$client->readdata = array();
									$client->readopen = false;
									@fclose($info["fp"]);

									$sessionhelper->StopChannel($client);

									unset($tracker[$id]);
								}
								else
								{
									$client->readdata[0] = (string)substr($client->readdata[0], $result2);
									if ($client->readdata[0] === "")  array_shift($client->readdata);
								}
							}
							else if ($info["protocol"] === "udp")
							{
								$result2 = stream_socket_sendto($info["fp"], $client->readdata[0], 0, $info["ipaddr"]);
								if ($result2 > 0)
								{
									$client->readdata[0] = (string)substr($client->readdata[0], $result2);
									if ($client->readdata[0] === "")  array_shift($client->readdata);
								}
							}
						}
					}

					if ($info["protocol"] === "udp" && $info["ts"] < time() - 6 * 60 * 60)
					{
						$sessionhelper->StopChannel($client);

						unset($tracker[$id]);
					}
				}

				// Attempt to send and receive data to/from the resilient IP server.
				$result = $sessionhelper->ProcessServerData();
				if (!$result["connected"])  $currstate = "verify_session";

				// Do something with removed clients.
				foreach ($result["removed"] as $id => $client)
				{
					if (isset($tracker[$id]))
					{
						$info = $tracker[$id];
						if ($info["protocol"] === "tcp")  @fclose($info["fp"]);

						unset($tracker[$id]);
					}
				}

				break;
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