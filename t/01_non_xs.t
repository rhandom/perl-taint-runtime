#!perl -T

use Test::More tests => 7;
BEGIN { use_ok('Taint::Runtime') };

Taint::Runtime->import(qw(taint_enabled
                          taint
                          untaint
                          is_tainted
                          ));

ok(taint_enabled(), "Taint is On");

my $data = "foo";
ok(! is_tainted($data), "No false positive on is_tainted");

my $copy = taint($data);
ok(is_tainted($copy), "Made a tainted copy");

taint(\$data);
ok(is_tainted($data), "Tainted it directly");

$copy = untaint($data);
ok(! is_tainted($copy), "Made a clean copy");

untaint(\$data);
ok(! is_tainted($data), "Clean it directly");
