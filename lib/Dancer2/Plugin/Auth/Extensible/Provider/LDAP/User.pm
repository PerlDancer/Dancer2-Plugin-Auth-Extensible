package Dancer2::Plugin::Auth::Extensible::Provider::LDAP::User;

use Dancer2::Core::Types qw/HashRef Str/;
use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::User";
use namespace::clean;

our $VERSION = '0.612';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::LDAP::User - a User class for Dancer2::Plugin::Auth::Extensible::Provider::LDAP

=head1 ATTRIBUTES

Addtributes in addition to those from L<Dancer2::Plugin::Auth::Extensible::Role::User>.

=head2 dn

The DN of this user.

=cut

has dn => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

=head2 attributes

A hash reference of other attributes returned from the LDAP database.

=cut

has attributes => (
    is      => 'ro',
    isa     => HashRef,
    default => sub { +{} },
);

1;
