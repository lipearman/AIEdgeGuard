<?php
// EdgeGuard PHP Lab — minimal PHP target for CGI injection testing
// (the WAF blocks attack payloads BEFORE they reach this file)
header('Content-Type: text/plain; charset=utf-8');
echo "PHP Lab OK\n";
echo "PHP version: " . PHP_VERSION . "\n";
echo "SAPI: " . php_sapi_name() . "\n";
echo "query: " . ($_SERVER['QUERY_STRING'] ?? '') . "\n";
