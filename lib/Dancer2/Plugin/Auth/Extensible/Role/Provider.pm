package Dancer2::Plugin::Auth::Extensible::Role::Provider;

use Crypt::SaltedHash;
use Moo::Role;
requires qw(authenticate_user get_user_details get_user_roles);

our $VERSION = '0.613';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Role::Provider - base role for authentication providers

=head1 DESCRIPTION

Base L<Moo::Role> for authentication providers.

Also provides secure password matching which automatically handles crypted
passwords via Crypt::SaltedHash.

=head1 ATTRIBUTES

=head2 plugin

The calling L<Dancer2::Plugin::Auth::Extensible> object.

Required.

=cut

has plugin => (
    is       => 'ro',
    required => 1,
    weaken   => 1,
);

=head2 disable_roles

Defaults to the value of L<Dancer2::Plugin::Auth::Extensible/disable_roles>.

=cut

has disable_roles => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->plugin->disable_roles },
);

=head2 encryption_algorithm

The encryption_algorithm used by L</encrypt_password>.

Defaults to 'SHA-512';

=cut

has encryption_algorithm => (
    is      => 'ro',
    default => 'SHA-512',
);

=head1 METHODS

=head2 match_password $given, $correct

Matches C<$given> password with the C<$correct> one.

=cut

sub match_password {
    my ( $self, $given, $correct ) = @_;

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
    if ( $correct =~ /^{.+}/ ) {

        # Looks like a crypted password starting with the scheme, so try to
        # validate it with Crypt::SaltedHash:
        return Crypt::SaltedHash->validate( $correct, $given );
    }
    else {
        # Straightforward comparison, then:
        return $given eq $correct;
    }
}

=head2 encrypt_password $password

Encrypts password C<$password> with L</encryption_algorithm>
and returns the encrypted password.

=cut

sub encrypt_password {
    my ( $self, $password ) = @_;
    my $crypt =
      Crypt::SaltedHash->new( algorithm => $self->encryption_algorithm );
    $crypt->add($password);
    $crypt->generate;
}

=head1 METHODS IMPLEMENTED BY PROVIDER

The following methods must be implemented by the consuming provider class.

=head2 required methods

=over

=item * authenticate_user

=item * get_user_details

=item * get_user_roles

=back

=head2 optional methods

The following methods are optional and extend the functionality of the
provider.

=over

=item * set_user_details

=item * set_user_password

=item * password_expired

=back

=cut

1;

