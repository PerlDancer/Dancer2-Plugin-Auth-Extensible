package Dancer2::Plugin::Auth::Extensible::Provider::LDAP::User;

use Dancer2::Core::Types qw/Str/;
use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::User";
use namespace::clean;

our $VERSION = '0.612';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::LDAP::User - a User class for Dancer2::Plugin::Auth::Extensible::Provider::LDAP

=cut

has dn => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

1;
