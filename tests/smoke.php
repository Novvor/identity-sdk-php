<?php

declare(strict_types=1);

if (PHP_VERSION_ID < 80200 || ! is_dir(__DIR__.'/../src')) {
    fwrite(STDERR, "Package source layout is invalid.\n");
    exit(1);
}

echo "Package source layout is present.\n";
