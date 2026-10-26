<?php
/**
 * vigil IAST sensor for PHP.
 *
 * Deploy: add to php.ini or .htaccess:
 *   auto_prepend_file = /path/to/sensor.php
 * Set VIGIL_CALLBACK_URL to the vigil IAST server.
 */

define('VIGIL_CALLBACK', getenv('VIGIL_CALLBACK_URL') ?: 'http://host.docker.internal:7880/api/v1/sink');
define('VIGIL_PREFIX', 'VIGIL_TAINT_');
define('VIGIL_SUFFIX', '_TAINT_VIGIL');

function vigil_check($value, $sink_type) {
    $s = (string)$value;
    if (strpos($s, VIGIL_PREFIX) === false || strpos($s, VIGIL_SUFFIX) === false) return;
    preg_match('/VIGIL_TAINT_([a-f0-9]{8})_/', $s, $m);
    $marker_id = $m[1] ?? '';
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);
    $stack = array_map(function($f) {
        return ($f['file'] ?? '?') . ':' . ($f['line'] ?? '?');
    }, $trace);
    $data = json_encode([
        'marker_id'   => $marker_id,
        'sink_type'   => $sink_type,
        'sink_value'  => substr($s, 0, 500),
        'stack_trace' => implode(' -> ', $stack),
        'timestamp'   => date('c'),
    ]);
    @file_get_contents(VIGIL_CALLBACK, false, stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-Type: application/json',
            'content' => $data,
            'timeout' => 1,
        ]
    ]));
}
