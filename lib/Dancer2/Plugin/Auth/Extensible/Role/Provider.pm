package Dancer2::Plugin::Auth::Extensible::Role::Provider;

use Crypt::SaltedHash;
use Safe::Isa;
use Sub::Quote 'quote_sub';
use Moo::Role;
requires qw(authenticate_user get_user_details get_user_roles);

our $VERSION = '0.500';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Role::Provider - base role for authentication providers

=head1 DESCRIPTION

Base L<Moo::Role> for authentication providers.

Also provides secure password matching which automatically handles crypted
passwords via Crypt::SaltedHash.

=head1 ATTRIBUTES

=head2 realm_settings

Hash reference containing realm settings.

Required.

=cut

has realm_settings => (
    is  => 'ro',
    isa => quote_sub(
        q{ die "realm_settings must be a hash reference"
           unless ref( $_[0] ) eq 'HASH' }
    ),
    default  => sub { {} },
    required => 1,
);

=head2 realm_dsl

Realm DSL object.

Required.

=cut

has realm_dsl => (
    is       => 'ro',
    required => 1,
);

=head1 METHODS

=head2 match_password($given, $correct)

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

=head2 encrypt_password($password, $algorithm)

Encrypts password C<$password> with C<$algorithm> which defaults to SHA-1
and returns the encrypted password.

=cut

sub encrypt_password {
    my ( $self, $password, $algorithm ) = @_;
    $algorithm ||= 'SHA-1';
    my $crypt = Crypt::SaltedHash->new( algorithm => $algorithm );
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

sub BUILDARGS {
    my $class = shift;
    my %args;
    if (   @_ == 2
        && ref( $_[0] ) eq 'HASH'
        && $_[1]->$_isa('Dancer2::Core::DSL') )
    {
        # deprecated calling notation
        warn 'new($realm_settings, $dsl) is deprecated.';
        $args{realm_settings} = shift;
        $args{realm_dsl}      = shift;
    }
    else {
        %args = @_ == 1 ? %{ $_[0] } : @_;
    }
    return \%args;
}

1;

