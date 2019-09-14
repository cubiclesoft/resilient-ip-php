<?php
	// Resilient IP server installation tool.
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

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"?" => "help"
		),
		"rules" => array(
			"help" => array("arg" => false)
		)
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "Resilient IP server installation command-line tool\n";
		echo "Purpose:  Installs the resilient IP server.\n";
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

	// Create a certificate chain if it does not already exist.
	if (!file_exists($rootpath . "/cert.pem") || !file_exists($rootpath . "/cert.key"))
	{
		echo "Creating CA and server certificates... (this can take a while)\n";

		require_once $rootpath . "/support/phpseclib/Crypt/RSA.php";
		require_once $rootpath . "/support/phpseclib/Math/BigInteger.php";
		require_once $rootpath . "/support/phpseclib/File/X509.php";

		// Generate the CSR.
		echo "\tGenerating 4096 bit CA private key and CSR...\n";

		$rsa = new Crypt_RSA();
		$data = $rsa->createKey(4096);

		$ca_privatekey = new Crypt_RSA();
		$ca_privatekey->loadKey($data["privatekey"]);

		$ca_publickey = new Crypt_RSA();
		$ca_publickey->loadKey($data["publickey"]);

		$csr = new File_X509();
		$csr->setPrivateKey($ca_privatekey);
		$csr->setPublicKey($ca_publickey);

		// Use the specified commonName.
		$csr->removeDNProp("id-at-commonName");
		if (!$csr->setDNProp("id-at-commonName", "Class 1 Certificate Authority"))  CLI::DisplayError("Unable to set commonName (common name) in the CSR.");

		// Have to sign, save, and load the CSR to add extensions.
		$csr->loadCSR($csr->saveCSR($csr->signCSR("sha256WithRSAEncryption")));

		$keyusage2 = explode(",", "keyCertSign, cRLSign");
		foreach ($keyusage2 as $num => $val)  $keyusage2[$num] = trim($val);
		if (!$csr->setExtension("id-ce-keyUsage", $keyusage2))  CLI::DisplayError("Unable to set extension keyUsage in the CSR.");

		$domains2 = array();
		$domains2[] = array("dNSName" => "Class 1 Certificate Authority");
		if (!$csr->setExtension("id-ce-subjectAltName", $domains2))  CLI::DisplayError("Unable to set extension subjectAltName in the CSR.");

		// Sign and save the CSR.
		$ca_csr = $csr->saveCSR($csr->signCSR("sha256WithRSAEncryption"));

		// Generate the certificate.
		echo "\tGenerating CA certificate...\n";

		$issuer = new File_X509();
		$issuer->loadCSR($ca_csr);
		$issuer->setPrivateKey($ca_privatekey);
		if ($issuer->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$subject = new File_X509();
		$subject->loadCSR($ca_csr);
		if ($subject->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$certsigner = new File_X509();
		$certsigner->makeCA();
		$certsigner->setStartDate("-1 day");
		$certsigner->setEndDate("+3650 day");
		$certsigner->setSerialNumber("1", 10);

		$signed = $certsigner->sign($issuer, $subject, "sha256WithRSAEncryption");
		if ($signed === false)  CLI::DisplayError("Unable to self-sign CSR.");
		$ca_cert = $certsigner->saveX509($signed);


		echo "\tGenerating 4096 bit server private key and CSR...\n";

		$rsa = new Crypt_RSA();
		$data = $rsa->createKey(4096);

		$server_privatekey = new Crypt_RSA();
		$server_privatekey->loadKey($data["privatekey"]);

		$server_publickey = new Crypt_RSA();
		$server_publickey->loadKey($data["publickey"]);

		$csr = new File_X509();
		$csr->setPrivateKey($server_privatekey);
		$csr->setPublicKey($server_publickey);

		// Use the specified commonName.
		$csr->removeDNProp("id-at-commonName");
		if (!$csr->setDNProp("id-at-commonName", "Resilient IP Server"))  CLI::DisplayError("Unable to set commonName (common name) in the CSR.");

		// Have to sign, save, and load the CSR to add extensions.
		$csr->loadCSR($csr->saveCSR($csr->signCSR("sha256WithRSAEncryption")));

		$keyusage2 = explode(",", "digitalSignature, keyEncipherment, keyAgreement");
		foreach ($keyusage2 as $num => $val)  $keyusage2[$num] = trim($val);
		if (!$csr->setExtension("id-ce-keyUsage", $keyusage2))  CLI::DisplayError("Unable to set extension keyUsage in the CSR.");

		$domains2 = array();
		$domains2[] = array("dNSName" => "Resilient IP Server");
		if (!$csr->setExtension("id-ce-subjectAltName", $domains2))  CLI::DisplayError("Unable to set extension subjectAltName in the CSR.");

		// Sign and save the CSR.
		$server_csr = $csr->saveCSR($csr->signCSR("sha256WithRSAEncryption"));

		// Generate the certificate.
		echo "\tGenerating server certificate...\n";

		$issuer = new File_X509();
		$issuer->loadX509($ca_cert);
		$issuer->setPrivateKey($ca_privatekey);

		$subject = new File_X509();
		$subject->loadCSR($server_csr);
		if ($subject->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$certsigner = new File_X509();
		$certsigner->setStartDate("-1 day");
		$certsigner->setEndDate("+3650 day");
		$certsigner->setSerialNumber("2", 10);

		$signed = $certsigner->sign($issuer, $subject, "sha256WithRSAEncryption");
		if ($signed === false)  CLI::DisplayError("Unable to self-sign CSR.");
		$server_cert = $certsigner->saveX509($signed);

		file_put_contents($rootpath . "/cert.pem", $server_cert . "\n" . $ca_cert);
		file_put_contents($rootpath . "/cert.key", $server_privatekey->getPrivateKey());
		@chmod($rootpath . "/cert.key", 0600);

		echo "\tDone.\n\n";
	}

	if (!isset($config["sslopts"]))  $config["sslopts"] = array();
	if (!isset($config["sslopts"]["local_cert"]) && file_exists($rootpath . "/cert.pem"))  $config["sslopts"]["local_cert"] = $rootpath . "/cert.pem";
	if (!isset($config["sslopts"]["local_pk"]) && file_exists($rootpath . "/cert.key"))  $config["sslopts"]["local_pk"] = $rootpath . "/cert.key";

	RESIP_SaveConfig($config);

	if (!isset($config["apikey"]))
	{
		$rng = new CSPRNG();
		$config["apikey"] = $rng->GenerateString(64);

		RESIP_SaveConfig($config);
	}

	if (!isset($config["host"]))
	{
		$ipv6 = CLI::GetYesNoUserInputWithArgs($args, "ipv6", "IPv6 host", "N");
		$config["host"] = ($ipv6 ? "[::0]" : "0.0.0.0");

		RESIP_SaveConfig($config);
	}

	if (!isset($config["session_port"]))
	{
		$port = (int)CLI::GetUserInputWithArgs($args, "session_port", "Session server port", "31265", "The Session server port number.  The Session server is a minimalist TCP/IP server that creates new sessions and retrieves information about the host.");
		if ($port < 0 || $port > 65535)  $port = 31265;
		$config["session_port"] = $port;

		RESIP_SaveConfig($config);
	}

	if (!isset($config["resip_port"]))
	{
		$port = (int)CLI::GetUserInputWithArgs($args, "resip_port", "Resilient IP server port", "31266", "The resilient IP server port number.  The resilient IP server is both a UDP/IP (preferred) and TCP/IP (fallback) server that performs the primary operations of the resilient IP protocol.  It only works with existing sessions created via the Session server.");
		if ($port < 0 || $port > 65535)  $port = 31266;
		$config["resip_port"] = $port;

		RESIP_SaveConfig($config);
	}

	if (!isset($config["allow_internet"]))
	{
		$config["allow_internet"] = CLI::GetYesNoUserInputWithArgs($args, "allow_internet", "Allow outbound Internet", "N", "Enabling outbound Internet access will allow any connection to be established/packet to be sent except to LAN and localhost IPs.");

		RESIP_SaveConfig($config);
	}

	if (!isset($config["whitelist"]))
	{
		$config["whitelist"] = array();

		do
		{
			$entry = CLI::GetUserInputWithArgs($args, "whitelist", "Whitelist outbound IP[:port]", "", (count($config["whitelist"]) ? "" : "Enter any IP addresses (and optional port numbers) to whitelist for outbound packets.  Wildcards for IP addresses are also accepted.  Leave empty to continue/skip."));
			if ($entry !== "")  $config["whitelist"][] = $entry;
		} while ($entry !== "");

		RESIP_SaveConfig($config);
	}

	echo "\n";
	echo "**********\n";
	echo "Configuration file is located at '" . $rootpath . "/config.dat'.  It can be manually edited.\n\n";
	echo "Master API key:  " . $config["apikey"] . "\n\n";
	echo "Session server port:  " . $config["session_port"] . "\n\n";
	echo "Resilient IP server port:  " . $config["resip_port"] . "\n\n";
	echo "Run 'server.php' to start the server.\n";
	echo "**********\n\n";

	echo "Done.\n";
?>