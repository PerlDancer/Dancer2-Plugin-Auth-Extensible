package Dancer2::Plugin::Auth::Extensible::Provider::Config::User;

use Dancer2::Core::Types qw/Str/;
use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::User";
use namespace::clean;

our $VERSION = '0.612';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::Config::User - a User class for Dancer2::Plugin::Auth::Extensible::Provider::Config

=cut

# We need the underlying hash to have user/pass for backward-compatibility
# with code that expects these two rather than username/password of
# a normal User object. At some point we'll add deprecation via
# a warning in BUILD.

has user => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

has '+username' => (
    lazy    => 1,
    default => sub { $_[0]->user },
);

has pass => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

has '+password' => (
    lazy    => 1,
    default => sub { $_[0]->pass },
);

1;
