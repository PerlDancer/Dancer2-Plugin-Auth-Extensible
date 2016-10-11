package Dancer2::Plugin::Auth::Extensible::Role::User;

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Role::User

=cut

use Dancer2::Core::Types qw/ArrayRef Str/;
use List::Util qw/any/;
use Moo::Role;

=head1 ATTRIBUTES

=head2 name

The user's full name

=cut

has name => (
    is      => 'ro',
    isa     => Str,
    default => '',
);

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
);

=head2 roles

An array reference of C<Role> objects.

=cut

has roles => (
    is      => 'ro',
    isa     => ArrayRef,
    default => sub { [] },
);

=head1 METHODS

=head2 check_password $password

Checks whether the supplied plain-text C<$password> matches the user's
L</password>. Returns a true value if user has a L</password> and
passwords match, otherwise returns a false value.

=cut

sub check_password {
    my ( $self, $given ) = @_;
    return 0 unless ( $self->password && $given );

    # Code cargo-culted from Dancer2::Plugin::Auth::Extensible::Role::Provider
    # method 'match_password' including all original comments.

    # TODO: perhaps we should accept a configuration option to state whether
    # passwords are crypted or not, rather than guessing by looking for the
    # {...} tag at the start.
    # I wanted to let it try straightforward comparison first, then try
    # Crypt::SaltedHash->validate, but that has a weakness: if a list of hashed
    # passwords got leaked, you could use the hashed password *as it is* to log
    # in, rather than cracking it first.  That's obviously Not Fucking Good.
    # TODO: think about this more.  This shit is important.  I'm thinking a
    # config option to indicate whether passwords are crypted - yes, no, auto
    # (where auto would do the current guesswork, and yes/no would just do as
    # told.)
    if ( $self->password =~ /^{.+}/ ) {

        # Looks like a crypted password starting with the scheme, so try to
        # validate it with Crypt::SaltedHash:
        return Crypt::SaltedHash->validate( $self->password, $given );
    }
    else {
        # Straightforward comparison, then:
        return $given eq $self->password;
    }
}

=head2 has_role $role

Returns true if user has the role C<$role>.

=cut

sub has_role {
    my ( $self, $role ) = @_;
    return any { $_ eq $role } @{ $self->roles };
}

1;
