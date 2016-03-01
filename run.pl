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
$ds->set_edns(1);
#$ds->set_mdns(1);

#$ds->set_server("192.168.0.1");
$ds->set_server("8.8.8.8");
#my @query = ("www.google.com", "www.yahoo.co.jp");
#my @query = ("www.google.com");
my @query = ("www.yahoo.co.jp");
#my @query = ("182.22.70.251");
#$ds->setType('TXT');

#$ds->set_server("224.0.0.251");
#$ds->set_port(5353);
#my @query = ("_http._tcp.update.freebsd.org");
#my @query = ("_irkit._tcp.local");
#$ds->setType('SRV');
#$ds->set_type('PTR');

$ds->set_query(\@query);
$ds->dump;

$ds->execute;

my $results = $ds->get_results;
$ds->dump($results);

for my $result (@$results){
    print "headers: \n" , $ds->get_headers($result);
    print "is_error: \n", $ds->is_error($result);
    print "\n";
    print "get_answer:\n", $ds->get_answer($result);
    print "\n";
    print "get_authority:\n", $ds->get_authority($result);
    print "\n";
    print "get_additional:\n", $ds->get_additional($result);
    print "\n";
}


#処理時間を計算して小数点以下を3桁に丸めて表示
printf("%0.5f",Time::HiRes::time - $start_time);

__END__
