# t/02_new.t
use strict;
use warnings;
use Test::More;
use Test::Exception;
use DNS_SIMPLE;

subtest 'no args' => sub {
    my $obj = DNS_SIMPLE->new;
    isa_ok $obj, 'DNS_SIMPLE';
};

subtest 'foo => bar' => sub {
    my $obj = DNS_SIMPLE->new(foo => 'bar');
    isa_ok $obj, 'DNS_SIMPLE';;
};

subtest 'SERVER => 127.0.0.1, PORT => 5353, QUERY => [127.0.0.1, www.example.com], TYPE => PTR, TIMEOUT => 1, EDNS => 1' => sub {
    my $obj = DNS_SIMPLE->new(
        SERVER => '127.0.0.1',
        PORT => 5353,
        QUERY => [ '127.0.0.1', 'www.example.com' ],
        TYPE => 'PTR',
        TIMEOUT => 1,
        EDNS => 1,
        );
    isa_ok $obj, 'DNS_SIMPLE';
    diag explain $obj;
    note explain $obj;
};

subtest 'SERVER => 127.0.0.1, PORT => 5353, QUERY => [127.0.0.1, www.example.com], TYPE => PTR, TIMEOUT => 1, EDNS => 1, RESULTS => [foo]' => sub {
    dies_ok {
        my $obj = DNS_SIMPLE->new(
            SERVER => '127.0.0.1',
            PORT => 5353,
            QUERY => [ '127.0.0.1', 'www.example.com' ],
            TYPE => 'PTR',
            TIMEOUT => 1,
            EDNS => 1,
            RESULTS => ['foo'],
            );
    };
};

subtest 'SERVER => 127.0.0.1, PORT => 5353, QUERY => [127.0.0.1, www.example.com], TYPE => PTR, TIMEOUT => 1, EDNS => 1, ID => 100' => sub {
    dies_ok {
        my $obj = DNS_SIMPLE->new(
            SERVER => '127.0.0.1',
            PORT => 5353,
            QUERY => [ '127.0.0.1', 'www.example.com' ],
            TYPE => 'PTR',
            TIMEOUT => 1,
            EDNS => 1,
            ID => 100,
            );
    };
};

subtest 'SERVER => 127.0.0.1, PORT => 5353, QUERY => 127.0.0.1, TYPE => PTR, TIMEOUT => 1, EDNS => 1, ID => 100' => sub {
    dies_ok {
        my $obj = DNS_SIMPLE->new(
            SERVER => '127.0.0.1',
            PORT => 5353,
            QUERY => '127.0.0.1',
            TYPE => 'PTR',
            TIMEOUT => 1,
            EDNS => 1,
            );
    };
};


done_testing;
