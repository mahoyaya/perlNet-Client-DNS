#!/usr/bin/env perl
use strict;
use warnings;
use Time::HiRes;

#開始時間を取得
my $start_time = Time::HiRes::time;

use lib "./lib";
use DNS_SIMPLE;

my $ds = DNS_SIMPLE->new();
$ds->dump;

$ds->setServer("192.168.0.1");
#my @query = ("www.google.com", "www.yahoo.co.jp");
my @query = ("www.google.com");
#my @query = ("www.yahoo.co.jp");
#my @query = ("182.22.70.251");
$ds->setQuery(\@query);
$ds->setType('TXT');
$ds->execute();

$ds->dump;

#処理時間を計算して小数点以下を3桁に丸めて表示
printf("%0.5f",Time::HiRes::time - $start_time);

__END__
