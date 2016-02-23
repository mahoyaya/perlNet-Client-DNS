package DNS_SIMPLE;
our $VERSION = '0.00001';
use strict;
use Carp;
use JSON; #別実装する
use Time::HiRes qw(usleep);
#use QueryFormat;

#my %reqid = {};
my $results = [];

sub new {
    my $class = shift;
    my $self = {
        SERVER => undef,
        PORT => 53,
        QUERY => [],
        TYPE => 'A',
        #ID => \%reqid,
        ID => {},
        TIMEOUT => 3,
        RESULTS => $results,
        EDNS => 0, #  Extension Mechanisms for DNS  EDNS0**3
    };
    bless($self, $class);
    return $self;
}

sub setEDNS {
    my $self = shift;
    my $bool = shift;
    if( $bool ) {
        $bool = 1;
    } else {
        $bool = 0;
    }
    $self->{EDNS} = $bool;
    return $bool;
}

sub setServer {
    my $self = shift;
    my $server = shift;
    if ( $server ) {
        $self->{SERVER} = gethostbyname($server);
    }
    return $self->{SERVER};
}

sub setPort {
    my $self = shift;
    my $port = shift;
    if ( $port ) {
        $self->{PORT} = getprotobyname($port) if $port =~ m/^\w+$/;
        $self->{PORT} = $port if $port =~ m/^\d+$/;
    }
    return $self->{PORT};
}

sub setQuery {
    my $self = shift;
    my $aref_query = shift;
    my @q = @$aref_query;
    push @{$self->{QUERY}}, $_ for @q;
    return $self->{QUERY};
}

sub setType {
    my $self = shift;
    my $type = shift;
    if ( $type ) {
        $self->{TYPE} = $type if $type =~ m/^[a-zA-Z]{1,5}$/;
        $self->{TYPE} = $type if $type =~ m/^(?:[1-9]|1[0-6])$/;
        $self->{TYPE} = $type if $type =~ m/^28$/;
        $self->{TYPE} = $type if $type =~ m/^33$/;
    }
    return $self->{TYPE};
}

sub setTimeout {
    my $self = shift;
    my $to = shift;
    if ( $to ) {
        $self->{TIMEOUT} = $to if $to > 0 && $to < 255 && $to =~ m/^[0-9]+$/;
    }
    return $self->{TIMEOUT};;
}

sub getTransactionID {
    my $self = shift;
    my $id = undef;
    while ( ! $id ) {
        my $lid = int(rand(65535)) + 1;
        if ( exists $self->{ID}->{$lid} ) {
            #carp("getTransactionID: generated transaction id was exists. $lid");
            next;
        }
        $id = $lid;
        $self->{ID}->{$id} = 1;
    }
    return $id;
}

sub getResults {
    my $self = shift;
    return $self->{RESULTS};
}

sub execute {
    my $self = shift;

    use Socket;
    use IO::Pipe;
    use IO::Select;
    use POSIX ":sys_wait_h";

    my $sock;
    my $rport = $self->{PORT};
    my $rhost = $self->{SERVER};
    my $data = "";
    my $href_h = {}; # handler

    my $qfr = {};
    my $qf = {};
    $qf->{QR} = '0';
    $qf->{OPCODE} = '0000';
    $qf->{AA} = '0';
    $qf->{TC} = '0';
    $qf->{RD} = '1';
    $qf->{RA} = '0';
    $qf->{Z} = '000';
    $qf->{RCODE} = '0000';
    $qf->{QUESTION} = '0000000000000001';
    $qf->{ANSWER} = '0000000000000000';
    $qf->{AUTHORITY} = '0000000000000000';
    $qf->{ADDITIONAL} = '0000000000000000';

    my $s = IO::Select->new;
    my @pids = ();
    my @pipes = ();
    while( my $q = shift @{$self->{QUERY}} ) {
        push @pipes, my $p = IO::Pipe->new;

        # generate transaction id
        my $id = $self->getTransactionID();
        $qf->{ID} = $id;

        my $pid = fork;
        if ($pid == 0) {
            # isChild
            $p->writer;

            # ヘッダ情報を送信可能な状態に変換
            $data = $self->makeHeaders($qf);
            # クエリー情報をデータを送信能可な状態に変換
            if ( uc($self->{TYPE}) eq "PTR" ) {
                #ポインタレコード
                my @r = reverse split /\./, $q;
                $q = (join '.', @r) . ".in-addr.arpa";
            }
            $data .= $self->makeQuery($q);
            $data .= $self->makeType($self->{TYPE});
            $data .= $self->makeClass();

            #carp("send data:" . unpack("H*", $data));

            local $@;
            # try
            eval {
                socket($sock, PF_INET, SOCK_DGRAM, 0) || confess "Cannot open socket: $!";
                my $sock_addr = pack_sockaddr_in $rport, $rhost || croak "Cannot pack $rhost:$rport: $!";

                # クエリー送信
                carp "request sending...";
                send($sock, $data, 0, $sock_addr) || croak "send failed $!\n";

                # もう送信しないので閉じる
                shutdown $sock, 1 if defined $sock; # stopped writing data

                # データを受信
                carp("waiting response...");

                my $rin = '';
                vec($rin, fileno($sock), 1) = 1;
                # データを待つ
                my ($nfound, $timeleft) = select(my $rout=$rin,undef,undef,$self->{TIMEOUT});

                if ($nfound) {
                    #local $SIG{ALARM} = sub { croak("recv failed $!") };
                    #alarm 3;
                    my $max = 512;
                    $max = 1410 if $self->{EDNS} > 0; # EDNSの推奨値1280-1410Bytes
                    recv($sock, my  $rbuff, $max, 0) || croak("recv failed $!");
                    #alarm 0;
                    carp(length($rbuff) . " Byte(s) data received.");

                    # データを受信する
                    my $tid = substr($rbuff, 0, 2); # 先頭２バイトからトランザクションIDを取得
                    my $ident16bit = substr($rbuff, 2, 2);
                    my $hq = substr($rbuff, 4, 2);
                    my $hans = substr($rbuff, 6, 2);
                    my $hauth = substr($rbuff, 8, 2);
                    my $hadd = substr($rbuff, 10, 2);
                    my $buff = substr($rbuff, 12, length($rbuff) + 1);
                    vec(my $identifer, 0, 16) = unpack("n", $ident16bit);
                    #carp("tid:" . unpack("H*", $tid) . "(" . unpack("n", $tid) .")");
                    #carp("ident16bit:". unpack("B16", $ident16bit) . "(" . unpack("n", $ident16bit) .")");

                    $qfr = {
                        QUES => [],
                        ANSS => [],
                        AUTS => [],
                        ADDS => [],
                    };
                    $qfr->{ID} = unpack("n", $tid);
                    $qfr->{QR} = vec($identifer, 7, 1); # vecはリトルエンディアンで処理される
                    $qfr->{OPCODE} = $self->readNetBin($ident16bit, 1, 4); # 2bit目から4bit分のデータを数値で取得する
                    $qfr->{AA} = vec($identifer, 2, 1);
                    $qfr->{TC} = vec($identifer, 1, 1);
                    $qfr->{RD} = vec($identifer, 0, 1);
                    $qfr->{RA} = vec($identifer, 15, 1);
                    $qfr->{Z} = $self->readNetBin($ident16bit, 9, 3);
                    $qfr->{RCODE} = $self->readNetBin($ident16bit, 12, 4);
                    $qfr->{QUESTION} = unpack("n", $hq);
                    $qfr->{ANSWER} = unpack("n", $hans);
                    $qfr->{AUTHORITY} = unpack("n", $hauth);
                    $qfr->{ADDITIONAL} = unpack("n", $hadd);
                    #carp Dumper($qfr);

                    #carp("$len bytes data received.");
                    #carp("unpack:" . unpack("H*", $buff));
                    #carp("received buffer:" . $buff);

                    # QUESTIONS以降のバッファを配列に格納
                    my @ary_buffer = $buff =~ /.{1}/gs;
                    # 全データを配列に格納
                    my @ary_buffer_full = ($tid . $ident16bit . $hq . $hans . $hauth . $hadd . $buff) =~ /.{1}/gs;

                    # QUESTIONSの取得
                    for ( my $i = 0; $i < $qfr->{QUESTION}; $i++ ) {
                        #carp "[$i]getQueries";
                        #carp join ",", $self->getQueries(\@ary_buffer);
                        push @{$qfr->{QUES}}, $self->getQueries(\@ary_buffer);
                    }

                    # ANSWERSの取得
                    for ( my $i = 0; $i < $qfr->{ANSWER}; $i++ ) {
                        #carp "[$i]getAnswers";
                        push @{$qfr->{ANSS}}, $self->getAnswers(\@ary_buffer, \@ary_buffer_full);
                    }

                    # AUTHORITYの取得
                    for ( my $i = 0; $i < $qfr->{AUTHORITY}; $i++ ) {
                        #carp "[$i]getAnswers(Authoritative names servers)";
                        push @{$qfr->{AUTS}},  $self->getAnswers(\@ary_buffer, \@ary_buffer_full);
                    }

                    # ADDITIONALの取得
                    for ( my $i = 0; $i < $qfr->{ADDITIONAL}; $i++ ) {
                        #carp "[$i]getAnswers(Additional records)";
                        push @{$qfr->{ADDS}}, $self->getAnswers(\@ary_buffer, \@ary_buffer_full);
                    }

                    ####################################################
                    #carp '======== DUMP ========' . Dumper($qfr);
                    #carp encode_json($qfr);
                    ####################################################

                } else {
                    # タイムアウト
                    carp("packet receive timeout.");
                }
            };
            # catch
            if( @$ ) {
                carp( @$ );
                shutdown $sock, 2 if defined $sock;
            }

            # データを親に送る
            my $h = {
                ID => $qf->{ID},
                PID => $$,
                RESULT => $qfr,
            };
            #carp Dumper($h);
            #carp "json size:" . length(encode_json($h));
            print $p encode_json($h);
            #carp  "close pipe";
            $p->close;
            #carp "shutdown sock";
            shutdown $sock, 2 if defined $sock;
            #carp "======== exit child ", $qf->{ID}, " ========";
            exit(0);

        } else {
            # isParent
            $p->reader;
            $p->blocking(0); # blockingしない
            $s->add($p);
            $href_h->{$pid} = $p;
            push(@pids, $pid);
            next;
        }
    }


    my $max = 1024 * 64;
    if( $^O eq "MSWin32" ) {
        #pidとpipeを関連付けたハッシュが空になるまでループ
        my $d = {};
        while ( %$href_h ) {
            #carp "==== while ==== ";
            my @ids = ();
            for ( keys %$href_h ) {
                my $pid = $_;
                my $kid = waitpid($_, WNOHANG);
                #carp "kid: " . $kid;
                while(read($href_h->{$_}, my $buff, $max)) {
                    #my $len = read($href_h->{$_}, my $buff, $max);
                    $d->{$pid} .= $buff;
                }
                #carp "dump json: " . $d->{$pid};
                #carp "read json size:" . length($d->{$pid});
                if($kid == -1 || $kid != 0){
                    # 該当pidの子プロセスが終了
                    my $h = decode_json($d->{$pid});
                    #carp "$_ is exited " . $buff;
                    push @{$self->{RESULTS}}, $h->{RESULT};
                    delete $href_h->{$pid};
                    delete $d->{$pid};
                    push @ids, $h->{ID};
                }
            }
            # トランザクションIDを消す
            for(@ids){
                delete $self->{ID}->{$_} if exists $self->{ID}->{$_};
            }
            #sleep 1;
            usleep(1000);
        }
    } else {
        # is Unix OS
        while(my @ready = $s->can_read()) {
            carp "========== while ===========";
            for (@ready) {
                my $buff = "";
                while(read($_, my $pbuff, $max)) {
                    confess "too many received data" if length($buff) > $max;
                    $buff .= $pbuff;
                }
                my $h = decode_json($buff);
                push @{$self->{RESULTS}}, $h->{RESULT};
                delete $self->{ID}->{$h->{ID}} if exists $self->{ID}->{$h->{ID}};
                $s->remove($_);
                $_->close;
            }
            waitpid(-1, WNOHANG);
            usleep(1000);
        }
        carp "============ out of while ============";
    }
    return 1;
}

sub makeQuery {
    my $self = shift;
    my $host = shift;
    my $binstr = '';
    carp($host);
    if ( $host ) {
        my @host_strings = split '\.', $host;
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

sub typeLookup {
    my $self = shift;
    my $type = shift;
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
        AAAA => 28,
        SRV => 33, # Server Selection
    };
    if( $type =~ m/^(?:[1-9]|1[0-6])$/ ) {
        # １~１６の数値ならハッシュを値でソートして配列に格納
        my @key = sort { $t->{$a} <=> $t->{$b} } keys %$t;
        return $key[$type - 1];
    } elsif( $type =~ m/^28$/ ) {
        return 'AAAA';
    } elsif( $type =~ m/^33$/ ) {
        return 'SRV';
    } elsif( $type =~ m/^\w+$/a ) {
        # 文字列だったらハッシュに存在するか確認
        if ( exists $t->{$type} ) {
            return $t->{$type};
        } else {
            return 0;
        }
    }
    return 0;
}

sub makeType {
    my $self = shift;
    my $type = uc shift;
    my $rstr = undef;
    if ( $type ) {
        if ( $type =~ m/^(?:[1-9]|1[0-6])$/ ) {
            $rstr = $type;
        }
        if ( $type =~ m/^28$/ ) {
            $rstr = $type;
        }
        if ( $type =~ m/^33$/ ) {
            $rstr = $type;
        }
        if ( $self->typeLookup($type) ) {
            $rstr = $self->typeLookup($type);
        }
    }
    if ( ! $rstr ) {
        carp("makeType: invalid query type. set default type A.") if ! $rstr;
        $rstr = 1;
    }
    return pack("n", $rstr);
}

sub makeClass {
    my $self = shift;
    return pack('n', 1);
}

sub makeHeaders {
    my $self = shift;
    my $qf = shift;
    my $data = "";
    # トランザクションIDをnetwork用のビッグエンディアンのバイナリデータに変換
    $data .= pack("n", $qf->{ID});

    # テキストをバイナリデータに変換
    $data .= pack("B16", $qf->{QR} . $qf->{OPCODE} . $qf->{AA} . $qf->{TC} . $qf->{RD} . $qf->{RA} . $qf->{Z} . $qf->{RCODE});
    $data .= pack("B16", $qf->{QUESTION});
    $data .= pack("B16", $qf->{ANSWER});
    $data .= pack("B16", $qf->{AUTHORITY});
    $data .= pack("B16", $qf->{ADDITIONAL});
    return $data;
}

sub readNetBin {
    # $sビット目から$eビット分のビット列を数値変換する
    my $self = shift;
    my ($n, $s, $e) = @_;
    # バイナリを数値に変換する
    $n = unpack("n", $n); #ビッグエンティアン unsighned short として数値に変換する
    #carp($n);
    #carp( unpack("B16", pack("n", $n)) );
    my $bin = $n << $s;
    $bin = 0xffff & $bin;
    $bin = $bin >> (16 - $e);
    #carp( unpack("B16", pack("n", $bin)) );
    return $bin;
}

# ヘッダを取り除いた受信パケットのバイトデータ配列からQUERY部分を取り出す
sub getQueries {
    my $self = shift;
    my $aref = shift;
    my $str = "";
    my $i = 0;
    my $l = 0; # label count
    ($str, $l ) = $self->getQname($aref);
    if (length($str) > 0 ) {
        $str =~ s/.$//;
    } else {
        $str = '.';
    }

    # タイプを取得
    my $type .= shift @$aref;
    $type .= shift @$aref;
    $type = unpack("n", $type);
    $type = $self->typeLookup($type);


    # クラスを取得
    my $class .= shift @$aref;
    $class .= shift @$aref;
    $class = unpack("n", $class);

    my $st = {};
    $st->{NAME} = $str;
    $st->{TYPE} = $type;
    $st->{CLASS} = $class;

    #return $str, $type, $class;
    return $st;
}

# ヘッダとQUERYを取り除いた受信パケットのバイトデータ配列からANSWER部分を取り出す
sub getAnswers {
    use warnings;
    my $self = shift;
    my $aref = shift;
    my $aref_full = shift;
    my $str = "";
    my $l = 0; # label count
    #my $preference = -1; # type MX preference
    #my $length = -1; # type TXT text length

    #$self->dumpArray($aref, "0:");
    # ネームを取得
    ($str, $l ) = $self->getName($aref, $aref_full);
    if (length($str) > 0 ) {
        $str =~ s/.$//;
    } else {
        $str = '.';
    }

    #$self->dumpArray($aref, "1:");
    # タイプを取得
    my $type = shift @$aref;
    $type .= shift @$aref;
    $type = unpack("n", $type);
    $type = $self->typeLookup($type);


    #$self->dumpArray($aref, "2:");
    # クラスを取得
    my $class = shift @$aref;
    $class .= shift @$aref;
    $class = unpack("n", $class);

    #$self->dumpArray($aref, "3:");
    # TTLを取得
    my $ttl = shift @$aref;
    $ttl .= shift @$aref;
    $ttl .= shift @$aref;
    $ttl .= shift @$aref;
    $ttl = unpack("N", $ttl); # 32bit ビッグエンディアン

    #$self->dumpArray($aref, "4:");
    # データ長を取得
    my $dlen = shift @$aref;
    $dlen .= shift @$aref;
    $dlen = unpack("n", $dlen);

    #$self->dumpArray($aref, "6:");
    # データを取得
    my $data;
    for(my $i = 0; $i < $dlen; $i++) {
        $data .= shift @$aref;
    }
    my $st = {};
    $st->{NAME} = $str;
    $st->{TYPE} = $type;
    $st->{CLASS} = $class;
    $st->{TTL} = $ttl;
    $st->{DLENGTH} = $dlen;
    #carp "==============================type:" . $type;
    if ( $type eq "A" || $type eq "PTR" ) {
        my @ip = ();
        @ip = unpack("C*", $data);
        $data = join qw/./, @ip;
        $st->{ADDRESS} = $data;
    } elsif ( $type eq "AAAA" ) {
        my @ary = $data =~ m/(.{1})/sg;
        my @pip = ();
        my @ip = ();
        for (@ary){
            push @pip, unpack("H*", $_);
        }
        while(my $hex = shift @pip) {
            push @ip, $hex . (shift @pip);
        }
        $data = join qw/:/, @ip;
        my @zero = sort ( $data =~ m/((?::0000)+)/g );
        $data =~ s/$zero[$#zero]/:/ if @zero;
        $data =~ s/:0{1,3}/:/g;
        $st->{AAAAADDRESS} = $data;
    } elsif ( $type eq "CNAME" || $type eq "NS" ) {
        #carp "type $type convert data to QNAME";
        my @ary = $data =~ m/(.{1})/gs;
        my ( $pstr, $pl ) =  $self->getName(\@ary, $aref_full);
        $data = $pstr;
        $st->{DATA} = $data;
    } elsif ( $type eq "MX" ) {
        #carp "type $type convert data to QNAME";
        my $preference = unpack("n", substr($data, 0, 2)); # 先頭2ByteはPreference
        $data =~ s/^..(.+)/$1/s;
        my @ary = $data =~ m/(.{1})/gs;
        my ( $pstr, $pl ) =  $self->getName(\@ary, $aref_full);
        $data = $pstr;
        $st->{PREFERENCE} = $preference;
        $st->{DATA} = $data;
    } elsif ( $type eq "SOA" ) {
        #carp "type $type convert data to QNAME";
        my @ary = $data =~ m/(.{1})/gs;
        my ( $pstr, $pl ) =  $self->getName(\@ary, $aref_full);
        $st->{PNS} = $pstr;
        ( $pstr, $pl ) =  $self->getName(\@ary, $aref_full);
        $st->{RAMBOX} = $pstr;
        $st->{SERIAL} = unpack("N", join "", @ary[0..3]);
        $st->{REFRESH} = unpack("N", join "", @ary[4..7]);
        $st->{RETRY} = unpack("N", join "", @ary[8..11]);
        $st->{EXPIRE} = unpack("N", join "", @ary[12..15]);
        $st->{MINTTL} = unpack("N", join "", @ary[16..19]);
    } elsif ( $type eq "TXT" ) {
        my $length = unpack("C", substr($data, 0, 1)); # 先頭1Byteはlength
        $data =~ s/^.(.+)/$1/s;
        $st->{LENGTH} = $length;
        $st->{DARA} = $data;
    } elsif ( $type eq "SRV" ) {
        #carp "type $type convert data to QNAME";
        my @names = split '\.', $str;
        $st->{SERVICE} = shift @names;
        $st->{PROTOCOL} = shift @names;
        $st->{NAME} = join '.', @names;
        $st->{PRIORITY} = unpack("n", substr($data, 0, 2)); # 先頭1-2ByteはPriority
        $st->{WEIGHT} = unpack("n", substr($data, 2, 4)); # 先頭3-4ByteはWeight
        $st->{PORT} = unpack("n", substr($data, 4, 6)); # 先頭5-6ByteはPort
        $data =~ s/^......(.+)/$1/s;
        my @ary = $data =~ m/(.{1})/gs;
        my ( $pstr, $pl ) =  $self->getName(\@ary, $aref_full);
        $pstr =~ s/\.$//;
        $st->{TARGET} = $pstr;
    } else {
        $st->{DATA} = $data;
    }

    return $st;
}

sub getName {
    my $self = shift;
    my $aref = shift;
    my $aref_full = shift;
    my $str = "";
    my $l = 0;
    #$self->dumpArray( $aref,  "getName:" );
    while (my $b = shift @$aref) {
        my $byte = unpack("C", $b);
        #carp "byte:" . $byte . " hex:" . unpack("H*", $b);
        if( $byte > 0 && $byte < 64 ) {
            # ラベルとして処理
            #carp "isLABEL";
            unshift(@$aref, $b);
            my ($pstr, $pl ) = $self->getQname($aref);
            $str .= $pstr;
            $l += $pl;
        } elsif( $byte > 63 ) {
            # 64以上であれば圧縮ONなのでポインタとして処理
            #carp "isPointer";
            my $p = $byte >> 6; # ポインタである場合は先頭2bitが0b11
            confess("Malformed Packet") if $p != 3; # 10進数で3になること
            my $offset = unpack("n", $b . shift(@$aref)); # ポインタは2byteのデータなので次の1byteを連結してから数値化する
            $offset = $offset << 2; # 上位2bit（ポインタ）を消す
            $offset = $offset & 0xffff;
            $offset = $offset >> 2; # オフセットを取得
            #carp "offset:" . $offset;
            my @ary = @$aref_full[$offset..$#{$aref_full}]; # フルデータの配列からオフセット分取り除いたものを取得
            #carp $self->dumpArray( \@ary );
            my ($pstr, $pl, $pp )= $self->getQname(\@ary);
            $str .= $pstr;
            $l += $pl;
            if ( $pp > 63 ) {
                # 続くのはポインタ
                my ( $ppstr, $ppl ) = $self->getName(\@ary, $aref_full);
                $str .= $ppstr;
                $l += $ppl;
            }
            last;
        } elsif( $byte == 0 ) {
            #carp "isEnd";
            last;
        } else {
            confess "Malformed packet";
        }

    }
    return $str, $l;
}

# 配列からDNSのQNAMEフォーマットでNAMEを取り出す
sub getQname {
    my $self = shift;
    my $aref = shift;
    my $str = "";
    my $i = 0;
    my $l = 0; # label count
    my $p = undef; # pointer
    while (my $b = shift @$aref) {
        my $byte = unpack("C", $b);
        if ( $byte > 0 && $byte < 64) {
            # 1バイト以上64バイト未満であればそのバイト数取得する
            for( my $j = 0; $j < $byte; $j++ ) {
                $str .= shift @$aref;
                $i++
            }
            $str .= '.';
            $l++;
            #carp("qname${i}:" . $str);
        } else {
            # 0か64以上だったら終了
            $p = $byte;
            unshift(@$aref, $b) if $byte > 63;
            last;
        }
    }
    return $str, $l, $p;
}

sub dumpArray {
    # オクテットデータの配列を受け取り、文字か16進数で表示する
    my $self = shift;
    my $aref = shift;
    my $prefix = shift;
    my $str = undef;
    for ( @$aref ) {
        my $b = unpack("C", $_);
        if ( $b > 47 && $b < 58 || $b > 64 && $b < 91 || $b > 96 && $b < 123 ) {
            #可読文字ならそのまま出力
            $str .= " " . $_;
        } else {
            #可読不可ならHEXに変換
            $str .= uc(unpack("H*", $_));
        }
        $str .= " ";
    }
    $prefix ? $str = $prefix . " " . $str : 1;
    carp "dumpArray:" .  $str;
    return;
}

sub dump {
    my $self = shift;
    my $ref = shift;
    use Data::Dumper;
    if ( $ref ) {
        print Dumper($ref);
    } else {
        print Dumper($self);
    }
    return;
}
1;

__END__

mDNS
IPv4 224.0.0.251
IPv6 ff02::fb

############################
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
