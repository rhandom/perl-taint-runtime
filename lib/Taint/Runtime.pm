package Taint::Runtime;

=head1 NAME

Taint::Runtime - Runtime enable taint checking

=head1 CREDITS

C code was provided by "hv" on perlmonks.
http://perlmonks.org/?node_id=434086

=cut

use strict;
use Exporter;
use vars qw(@ISA %EXPORT_TAGS @EXPORT_OK @EXPORT $VERSION);
use XSLoader;

BEGIN {
  @ISA = qw(Exporter);
  %EXPORT_TAGS = (
                  'all' => [qw(
                               taint_start
                               taint_stop
                               taint_enabled
                               tainted
                               is_tainted
                               taint
                               untaint
                               taint_env
                               taint_deeply
                               ) ],
                  );
  @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
  @EXPORT = qw(taint_start taint_stop);

  $VERSION = '0.01';
  XSLoader::load('Taint::Runtime', $VERSION);
}

###----------------------------------------------------------------###

sub taint_start { _start_taint(); }

sub taint_stop  { _stop_taint() }

sub is_tainted { local $^W = 0; ! eval { eval(join "", '#', @_); 1 } }

sub taint_enabled { is_tainted(_tainted()) }

sub tainted { _tainted() }

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

sub taint_env {
  taint_deeply(\%ENV);
}

sub taint_deeply {
  my ($ref, $seen) = @_;

  return if ! defined $ref; # can undefined be tainted ?

  if (! ref $ref) {
    untaint \$_[0]; # better be modifyable
    return;

  } elsif (UNIVERSAL::isa($ref, 'SCALAR')) {
    untaint $ref;
    return;
  }

  ### avoid circular descent
  $seen ||= {};
  return if $seen->{$ref};
  $seen->{$ref} = 1;

  if (UNIVERSAL::isa($ref, 'ARRAY')) {
    taint_deeply($_, $seen) foreach @$ref;

  } elsif (UNIVERSAL::isa($ref, 'HASH')) {
    while (my ($key, $val) = each %$ref) {
      taint_deeply($key);
      taint_deeply($val, $seen);
      $ref->{$key} = $val;
    }
  } else {
    # not really sure if or what to do for GLOBS or CODE refs
  }
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

You probably shouldn't use this module.  The most common place to
use this script would be in a CGI type environment where the server
can be trusted.  This means that PERL5LIB and PERLLIB are known
entities and the modules in them can be trusted.

Generally tainting should be started before any processing of user
data is done.  For example, taint_start should be called before
CGI parameters are loaded or user files or filenames are read.

In general - the more secure your script needs to be - the earlier
on in your program that tainting should be enabled.  You probably really
don't want to use this module in a setuid environment - in those cases
-T on the commandline is the best policy.

=head1 NON-EXPORTABLE XS FUNCTIONS

=over 4

=item _start_taint()

Sets PL_tainting

=item _stop_taint()

Sets PL_tainting

=item _tainted()

Returns a zero length tainted string.

=back

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

=item taint_env

Convenience function that taints the values of %ENV.

=item taint_deeply

Convenience function that attempts to deply recurse a
structure and mark it as tainted.

=back

=head1 AUTHOR

Paul Seamons

=cut
