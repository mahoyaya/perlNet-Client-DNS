#!/usr/bin/env perl

use strict;
use warnings;

use Time::HiRes;

my $cnt = 1_000_000;
$cnt = 1;

my $st;

$st = Time::HiRes::time();

for(my $i = 0; $i < $cnt; $i++) {
    runvec(0xffff);
}
print runvec(0xffff), "\n";

printf "%0.5f", Time::HiRes::time() - $st;
print "\n";

$st = Time::HiRes::time();

for(my $i = 0; $i < $cnt; $i++) {
    runshift(0xffff);
}
print runshift(0xffff), "\n";

printf "%0.5f", Time::HiRes::time() - $st;
print "\n";

sub runvec {
    my $n = shift;
    my $foo;
    my @d = ();
    vec($foo, 0, 16) = $n;
    for(my $i = 0; $i<16; $i++){
	push(@d, vec($foo, $i, 1));
    }
    return @d;
}

sub runshift {
    my $n = shift;
    my @d = ();
    my $b = $n;
    for(my $i = 0; $i<16; $i++) {
	my $bin = $b << $i;
	$bin = 0xffff & $bin;
	$bin = $bin >> 15;
	push(@d, $bin);
    }
    return @d;
}
__END__
