<?php
// Get raw POST data
$data = file_get_contents("php://input");

// Decode JSON
$json = json_decode($data, true);
if (!$json || !isset($json['surveyCode'])) {
    http_response_code(400);
    echo "No surveyCode provided";
    exit;
}

$code = intval($json['surveyCode']); // sanitize

// Folder for saving codes
$folder = "participant_codes";
if (!is_dir($folder)) {
    mkdir($folder, 0755, true); // create folder if missing
}

// Prepare line with timestamp
$timestamp = date("Y-m-d H:i:s");
$line = $timestamp . " | " . $code . PHP_EOL;

// Append to local file
$filePath = "$folder/codes_graz.txt";
file_put_contents($filePath, $line, FILE_APPEND | LOCK_EX);

?>
