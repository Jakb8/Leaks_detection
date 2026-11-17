<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\StreamedResponse;

class CsvExporter
{
    /**
     * @param list<string> $headers
     * @param iterable<list<scalar|null>> $rows
     */
    public function export(array $headers, iterable $rows, string $filename): StreamedResponse
    {
        $response = new StreamedResponse();
        $response->headers->add([
            'Content-Type' => 'text/csv; charset=UTF-8',
            'Content-Disposition' => sprintf('attachment; filename="%s"', $filename),
            'Cache-Control' => 'no-store',
        ]);
        $response->setCallback(static function () use ($headers, $rows): void {
            $handle = fopen('php://output', 'w');
            if ($handle === false) {
                return;
            }
            fputcsv($handle, $headers, ';');
            foreach ($rows as $row) {
                fputcsv($handle, array_map(static fn ($value) => is_bool($value) ? (int) $value : $value, $row), ';');
            }
            fclose($handle);
        });

        return $response;
    }
}
