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

	$context = stream_context_create();
	$mainfp = @stream_socket_client("tcp://127.0.0.1:4000", $errornum, $errorstr, 10, STREAM_CLIENT_CONNECT, $context);
	if ($mainfp === false)  CLI::DisplayError("Unable to connect to test server.", array("success" => false, "error" => HTTP::HTTPTranslate("Connect() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed"));

	function SendReceiveData($data)
	{
		global $mainfp;

		echo "Sending:  " . $data ."\n";
		fwrite($mainfp, $data . "\n");

		$line = fgets($mainfp);
		echo "Received:  " . rtrim($line) . "\n";
	}

	SendReceiveData("LOGIN");
	SendReceiveData("DATA");
	SendReceiveData("QUIT");

	while (!feof($mainfp))
	{
		fgets($mainfp);
	}
?>