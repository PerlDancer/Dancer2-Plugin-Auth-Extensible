package Dancer2::Plugin::Auth::Extensible::Role::User;

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Role::User

=cut

use Dancer2::Core::Types qw/ArrayRef Str/;
use Moo::Role;

=head1 ATTRIBUTES

=head2 username

The user's username. Required.

=cut

has username => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

=head2 password

The user's password.

There is no public reader method.

=over

=item writer: set_password

=back

=cut

has password => (
    is     => 'ro',
    isa    => Str,
    writer => 'set_password',
    reader => '_password',
);

=head2 roles

An array reference of C<Role> objects.

=cut

has roles => (
    is      => 'lazy',
    isa     => ArrayRef,
    default => sub { [] },
);

1;
