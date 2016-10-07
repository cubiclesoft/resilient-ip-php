<?php
	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/../client/support/cli.php";
	require_once $rootpath . "/../client/support/http.php";

	// Test TCP/IP server.  This is NOT the way to write a real server, but whatever.  It works.
	$context = stream_context_create();
	$mainfp = stream_socket_server("tcp://127.0.0.1:10000", $errornum, $errorstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
	if ($mainfp === false)  CLI::DisplayError("Unable to start test server.", array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"));

	do
	{
		// Wait for a connection.
		$readfps = array($mainfp);
		$writefps = array();
		$exceptfps = NULL;
		stream_select($readfps, $writefps, $exceptfps, NULL);

		$fp = @stream_socket_accept($mainfp, 0);
		if ($fp !== false)
		{
			echo "Client connected.\n";

			do
			{
				$cmd = trim(fgets($fp));
				echo "Received:  " . $cmd . "\n";

				if ($cmd === "LOGIN")  fwrite($fp, "Logged in.  Fantastic.\n");
				else if ($cmd === "DATA")  fwrite($fp, "Sending data.\n");
				else if ($cmd === "QUIT")  fwrite($fp, "Quitting.\n");

			} while ($cmd !== "" && $cmd !== "QUIT");

			fclose($fp);
		}
	} while (1);
?>