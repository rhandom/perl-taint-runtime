package Taint::Runtime;

=head1 NAME

Taint - Runtime enable taint checking

=head1 CREDITS

Inline C code was provided by "hv" on perlmonks.
http://perlmonks.org/?node_id=434086

=cut

use strict;
use base qw(Exporter);
use vars qw(%EXPORT_TAGS @EXPORT_OK @EXPORT $VERSION);

%EXPORT_TAGS = (
                'all' => [qw(
                             taint_start
                             taint_stop
                             taint_enabled
                             tainted
                             is_tainted
                             taint
                             untaint
                             ) ],
                );
@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
@EXPORT = qw();
$VERSION = '0.01';

require XSLoader;
XSLoader::load('Taint::Runtime', $VERSION);

###----------------------------------------------------------------###

sub is_tainted { local $^W = 0; ! eval { eval(join "", '#', @_); 1 } }

use vars qw($TAINTED);
BEGIN {
  $TAINTED = _tainted();
  if (! is_tainted($TAINTED)) {
    $TAINTED = substr join("", @ARGV, $ENV{'PATH'}, $ENV{'SHELL'}, $ENV{'HTTP_USER_AGENT'}, $0), 0, 0;
    if (! is_tainted($TAINTED) && open _RANDOM, "/dev/urandom") {
      sysread(_RANDOM, my $chr, 1);
      close _RANDOM;
      $TAINTED = substr $chr, 0, 0;
      $TAINTED = undef if ! is_tainted($TAINTED);
    }
  }
}

sub taint_start { _start_taint() }

sub taint_stop  { _stop_taint() }

sub taint_enabled { is_tainted($TAINTED) }

sub tainted {
  die "Could not get tainted data - or taint mode not enabled" if ! defined $TAINTED;
  return $TAINTED;
}

sub taint {
  my $str = shift;
  my $ref = ref($str) ? $str : \$str;
  $$ref = '' if ! defined $$ref;
  $$ref .= tainted();
  return ref($str) ? 1 : $str;
}

sub untaint {
  my $str = shift;
  my $ref = ref($str) ? $str : \$str;
  if (! defined $$ref) {
    $$ref = undef;
  } else {
    $$ref = ($$ref =~ /(.*)/) ? $1 : do { require Carp; Carp::confess("Couldn't find data to untaint") };
  }
  return ref($str) ? 1 : $str;
}

###----------------------------------------------------------------###

1;

__END__

=head1 SYNOPSIS

  #!/usr/bin/perl -w

  use strict;
  use Taint::Runtime qw(taint_start is_tainted
                        taint untaint
                        taint_enabled);

  ### other operations here

  taint_start(); # taint should become active

  print taint_enabled() ? "enabled\n" : "not enabled\n";

  my $var = taint("some string");

  print is_tainted($var) ? "tainted\n" : "not tainted\n";

  $var = untaint($var);
  # OR
  untaint \$var;

  print is_tainted($var) ? "tainted\n" : "not tainted\n";

=head1 DESCRIPTION

You probably shouldn't use this module.

=head1 FUNCTIONS

=over 4

=item taint_start

Start taint mode.

=item taint_stop

Stop taint mode.

=item taint

Taints the passed in variable.  Only works on writeable scalar values.
If a scalar ref is passed in - it is modified.  If a scalar is passed in
(non ref) it is copied, modified and returned.  If a value was undefined,
it becomes a zero length defined and tainted string.

  taint(\$var_to_be_tainted);

  my $tainted_copy = taint($some_var);

=item untaint

Untaints the passed in variable.  Only works on writeable scalar values.
If a scalar ref is passed in - it is modified.  If a scalar is passed in
(non ref) it is copied, modified and returned.  If a value was undefined
it becomes an untainted undefined value.

  untaint(\$var_to_be_untainted);

  my $untainted_copy = untaint($some_var);

=back

=item taint_enabled

Boolean - Is taint on.

=item tainted

Returns a zero length tainted string.

=item is_tainted

Boolean - True if the passed value is tainted.

=cut
