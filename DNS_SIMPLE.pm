package DNS_SIMPLE;
our $VWESION = '0.00001';
use strict;
use Carp;
use Class::Struct;

struct QueryFormat => {
    ID                 => '$', # 16bit, transaction id
    QR               => '$', # 1bit, query 0, reply 1
    OPCODE      => '$', # 4bit, standard 0, inverse 1, server status request 2
    AA               => '$', # 1bit, Authorative Answer
    TC                => '$', # 1bit, TurnCation, is fragment 1
    RD               => '$', # 1bit, Recursion Desired, request Recursion 1
    RA               => '$', # 1bit, Recursion Available, support Recursion 1
    PRT1            => '$', # 3bit, reserved bits, 000
    RCODE        => '$', # 4bit, no error 0, format error 1, server error 2, name error 3, undef 4, refuse 5
    QUESTION   => '$', # 16bit, question
    ANSWER     => '$', # 16bit, answer
    AUTHORITY  => '$', # 16bit, authority
    ADDITIONAL => '$', # 16bit, additional
};

my %reqid = {};

sub new {
    my $class = shift;
    my $self = {
	SERVER => undef,
	PORT => 53,
	QUERY => [],
	TYPE => 'A',
	ID => \%reqid,
    };
    bless($self, $class);
    return $self;
}

sub setServer {
    my $self = shift;
    my $server = shift;
    if ( $server ) {
	$self->{SERVER} = gethostbyname($server);
    }
    return 1;
}

sub setPort {
    my $self = shift;
    my $port = shift;
    if ( $port ) {
	$self->{PORT} = getprotobyname($port);
    }
    return 1;
}

sub setQuery {
    my $self = shift;
    my $aref_query = shift;
    my @q = @$aref_query;
    push @{$self->{QUERY}}, $_ for @q;
    return 1;
}

sub setType {
    my $self = shift;
    my $type = shift;
    if ( $type ) {
	$self->{TYPE} = $type if $type =~ m/^(?:[1-9]|1[0-6])/;
    }
    return 1;
}

sub getTransactionID {
    my $self = shift;
    my $id = undef;
    while ( ! $id ) {
	my $lid = int(rand(65536));
	if ( exists $self->{ID}->{$lid} ) {
	    carp("getTransactionID: generated transaction id was exists. $lid");
	    next;
	}
	$id = $lid;
	$self->{ID}->{$id} = 1;
    }
    return $id;
}

sub execute {
    my $self = shift;

    use Socket;
    my $sock;
    my $rport = $self->{PORT};
    my $rhost = $self->{SERVER};
    my $data = "";

    #$self->{QF} = QueryFormat->new(QR=>0x0001);
    my $qf = QueryFormat->new();
    $qf->QR("0");
    $qf->OPCODE("0000");
    $qf->AA("0");
    $qf->TC("0"); # fragment
    $qf->RD("1"); # request recursion
    $qf->RA("0");
    $qf->PRT1("000");
    $qf->RCODE("0000");
    $qf->QUESTION("0000000000000001");
    $qf->ANSWER("0000000000000000");
    $qf->AUTHORITY("0000000000000000");
    $qf->ADDITIONAL("0000000000000000");

    # generate transaction id
    my $id = getTransactionID();
    $qf->ID($id);
    carp Dumper($qf);

    #my $data = "";
    # トランザクションIDをnetwork用のビッグエンディアンのバイナリデータに変換
    $data .= pack("n", $qf->ID);

    # テキストをバイナリデータに変換
    $data .= pack("B16", $qf->QR . $qf->OPCODE . $qf->AA . $qf->TC . $qf->RD . $qf->RA . $qf->PRT1 . $qf->RCODE);
    $data .= pack("B16", $qf->QUESTION);
    $data .= pack("B16", $qf->ANSWER);
    $data .= pack("B16", $qf->AUTHORITY);
    $data .= pack("B16", $qf->ADDITIONAL);

    # クエリー情報をデータを送信可能なデータに変換
    my $q = shift @{$self->{QUERY}};
    $data .= $self->getQueryBinary($q);
    $data .= $self->getQueryType($self->{TYPE});
    $data .= $self->getQueryClass();

    carp(unpack("H*", $data));


    # ソケット作成
    # try
    eval {
	socket($sock, PF_INET, SOCK_DGRAM, 0) || croak "Cannot open socket: $!";
    };
    # catch
    if ( @$ ) {
	carp($@);

	# トランザクションIDを消す
	delete $self->{ID}->{$id} if exists $self->{ID}->{$id};

	# ソケットが残っていれば閉じる
	shutdown $sock, 2 if defined $sock;
    }

    # 親子で利用するパイプの作成
    pipe my $read, my $write;
    #select $read; $| = 1; select STDOUT;
    select $write; $| = 1; select STDOUT;
    binmode $read;
    binmode $write;

    my $pid = fork;
    if ($pid == 0) {
	# isChild
	# 不要なので閉じる
	close $read;
	# 受信ソケットを用意する
	# try
	eval {
	    #local $SIG{ALARM} = sub { croak("recv failed $!") };
	    #alarm 3;
	    recv($sock, my $buff, 512, 0) || croak("recv failed $!");
	    #alarm 0;
	    carp("buff len:" . length($buff));
	    # 受信データを親にデータを送る
	    print $write $buff;
	};
	# catch
	if( @$ ) {
	    carp( @$ );
	    shutdown $sock, 2 if defined $sock;
	}
	shutdown $sock, 2 if defined $sock;
	close $write if defined $write;
	exit(0);

    } else {
	# isParent
	# 不要なので閉じる
	close $write;

	# try
	eval {
	    my $sock_addr = pack_sockaddr_in $rport, $rhost || croak "Cannot pack $rhost:$rport: $!";

	    # クエリー送信
	    send($sock, $data, 0, $sock_addr) || croak "send failed $!\n";

	    # もう送信しないので閉じる
	    shutdown $sock, 1 if defined $sock; # stopped writing data

	    # 子供からのデータを受信
	    carp("waiting data from child");
	    my $rin = '';
	    vec($rin, fileno($read), 1) = 1;
	    # 3秒データを待つ
	    my ($nfound, $timeleft) = select(my $rout=$rin,undef,undef,3);
	    if ($nfound) {
		my $buff = '';
		my $len = 0;
		carp("data received from child");
		my $tidlen1 = read($read, my $tid, 2);
		#my $hlen1 = read($read, my $h1, 2);
		my $identlen = read($read, my $ident16bit, 2);
		my $hqlen = read($read, my $hq, 2);
		my $hanslen = read($read, my $hans, 2);
		my $hauthlen = read($read, my $hauth, 2);
		my $haddlen = read($read, my $hadd, 2);
		$len = read($read, $buff, 512);
		vec(my $identifer, 0, 16) = unpack("n", $ident16bit);
		carp($ident16bit);
		carp("tid:". unpack("H*", $tid) . "(" . unpack("n", $tid) .")");
		carp("ident16bit:". unpack("B16", $ident16bit) . "(" . unpack("n", $ident16bit) .")");
		carp("QR0:" . vec($identifer, 0, 1));
		carp("QR1:" . vec($identifer, 1, 1));
		carp("QR2:" . vec($identifer, 2, 1));
		carp("QR3:" . vec($identifer, 3, 1));
		carp("QR4:" . vec($identifer, 4, 1));
		carp("QR5:" . vec($identifer, 5, 1));
		carp("QR6:" . vec($identifer, 6, 1));
		carp("QR7:" . vec($identifer, 7, 1));
		carp("QR8:" . vec($identifer, 8, 1));
		carp("QR9:" . vec($identifer, 9, 1));
		carp("QR0:" . vec($identifer, 10, 1));
		carp("QR1:" . vec($identifer, 11, 1));
		carp("QR2:" . vec($identifer, 12, 1));
		carp("QR3:" . vec($identifer, 13, 1));
		carp("QR4:" . vec($identifer, 14, 1));
		carp("QR5:" . vec($identifer, 15, 1));
		carp("OPCODE:" . $self->getShiftData16b(unpack("n", $ident16bit), 0, 1));
		carp("OPCODE:" . $self->getShiftData16b(unpack("n", $ident16bit), 1, 4));
		carp("OPCODE:" . $self->getShiftData16b(unpack("n", $ident16bit), 7, 1));
		carp("OPCODE:" . $self->getShiftData16b(unpack("n", $ident16bit), 8, 1));
		carp("AA:" . vec($identifer, 5, 1));
		carp("TC:" . vec($identifer, 6, 1));
		carp("RD:" . vec($identifer, 7, 1));
		carp("RA:" . vec($identifer, 8, 1));
		#carp("PRT:" . vec($identifer, 9, 3));
		carp("RCODE:" . vec($identifer, 12, 4));
		carp("question:". unpack("n", $hq));
		carp("answer:". unpack("n", $hans));
		carp("authority:". unpack("n", $hauth));
		carp("additional:". unpack("n", $hadd));
		carp("$len bytes data received.");
		carp("unpack:" . unpack("H*", $buff));
		carp("pack:" . pack("C*", $buff));
	    } else {
		# タイムアウトなので子プロセスを殺す
		carp("packet receive timeout.");
		#kill(18, $pid);
		kill(9, $pid);
		wait();
	    }

	    # 終了したらトランザクションIDを消す
	    delete $self->{ID}->{$id} if exists $self->{ID}->{$id};
	};
	# catch
	if ( $@ ) {
	    carp( $@ );

	    # トランザクションIDを消す
	    delete $self->{ID}->{$id} if exists $self->{ID}->{$id};

	    # ソケットが残っていれば閉じる
	    close $read if defined $read;
	    shutdown $sock, 2 if defined $sock;
	}

	# 不要なので閉じる
	close $read;
	wait();
    }

    return;
}

sub getQueryBinary {
    my $self = shift;
    my $host = shift;
    my $binstr = '';
    carp($host);
    if ( $host ) {
	my @host_strings = split /\./, $host;
	my @d = ();
	push(@d, length($_)) for @host_strings;
	for( my $i = 0; $i < scalar @d; $i++ ) {
	    $binstr .= pack('C', $d[$i]);
	    $binstr .= $host_strings[$i];
	}
	$binstr .= pack('C', 0);
    }
    return $binstr;
}

sub getQueryType {
    my $self = shift;
    my $type = uc shift;
    my $rstr = undef;
    my $t = {
	A => 1,
	NS => 2,
	MD => 3,
	MF => 4,
	CNAME => 5,
	SOA => 6,
	MB => 7,
	MG => 8,
	MR => 9,
	NULL => 10,
	WKS => 11,
	PTR => 12,
	HINFO => 13,
	MINFO => 14,
	MX => 15,
	TXT => 16,
    };
    if ( $type ) {
	if ( $type =~ m/^(?:[1-9]|1[0-6])$/ ) {
	    $rstr = $type;
	}
	if ( exists $t->{$type} ) {
	    $rstr = $t->{$type};
	}
    }
    if ( ! $rstr ) {
	carp("getQueryType: invalid query type. set default type A.") if ! $rstr;
	$rstr = 1;
    }
    return pack("n", $rstr);
}

sub getQueryClass {
    my $self = shift;
    return pack('n', 1);
}

sub getShiftData16b {
    my ($n, $s, $e) = @_;
    my $bin = $n << $s - 1;
    $bin = 0xffff & $bin;
    return $bin >> (16 - $e);
}

sub dump {
    my $self = shift;
    use Data::Dumper;
    print Dumper($self);
    return;
}

1;

__END__
  print <<'EOT';
                                    0         1         2         3
                     unpack("V",$_) 01234567890123456789012345678901
  ------------------------------------------------------------------
  EOT

  for $w (0..3) {
      $width = 2**$w;
      for ($shift=0; $shift < $width; ++$shift) {
          for ($off=0; $off < 32/$width; ++$off) {
              $str = pack("B*", "0"x32);
              $bits = (1<<$shift);
              vec($str, $off, $width) = $bits;
              $res = unpack("b*",$str);
              $val = unpack("V", $str);
              write;
          }
      }
  }

  format STDOUT =
  vec($_,@#,@#) = @<< == @######### @>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  $off, $width, $bits, $val, $res
  .
