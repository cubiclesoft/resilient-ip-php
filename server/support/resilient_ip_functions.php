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

	function RESIP_GetBitsIntSize($val)
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

	function RESIP_PackInt($num)
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

	function RESIP_UnpackInt($data)
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


	// Check enabled extensions.
	if (!extension_loaded("openssl"))  CB_DisplayError("The 'openssl' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");
	if (!extension_loaded("zlib"))  CB_DisplayError("The 'zlib' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");
?>