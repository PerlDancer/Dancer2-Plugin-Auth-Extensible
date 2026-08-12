package Dancer2::Plugin::Auth::Extensible::Role::Provider;

use Crypt::Passphrase;
use Crypt::Passphrase::SaltedHash;
use Crypt::Passphrase::Argon2;
use Crypt::Passphrase::Linux;
use Moo::Role;
requires qw(authenticate_user);

our $VERSION = '0.712';

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
    weak_ref   => 1,
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

The encryption_algorithm used by L</encrypt_password>. (Required)

Defaults to 'Argon2'.

=cut

has encryption_algorithm => (
    is      => 'ro',
    default => sub { 
        { module => 'Argon2' }; 
    },
    coerce => sub { _parse_algorithm(shift); }
);

=head2 validator

The validator used by L</match_password>. (Optional)

Defaults to 'SaltedHash'.

=cut

has validator => (
    is      => 'ro',
    default => sub { 
        [ { module => 'SaltedHash' } ]; # GOST / HMAC-MD5 / HMAC-SHA-1 / MD2 / MD4 / MD5 / MD6 / SHA / SHA224 / SHA256 / SHA384 / SHA512
    },
    coerce  => sub { 
        my ($val) = @_;
        if (ref $val eq 'ARRAY') {
            return [ map { _parse_algorithm($_) } @$val ];
        }
        return [ _parse_algorithm($val) ];
    },
);

# { module => $x, type => $y // undef }
sub _parse_algorithm {
    my ($algorithm) = shift;
    return $algorithm if ref $algorithm;

    $algorithm =~ s/-//g;
    return {
        module => 'Linux',  
        type   => lc $algorithm, # sha512 / sha256 / md5 / apache_md5
    };
}

=head1 METHODS

=head2 match_password $given, $correct, $rehash_callback

Matches C<$given> password with the C<$correct> one and uses C<$rehash_callback> (Optional) to rehash & save
the password if different from the set encoder.

=cut

sub match_password {
    my ( $self, $given, $correct, $rehash_callback ) = @_;

    # If $correct is undefined, then do not attempt a match, otherwise an
    # uninnitialized warning will be thrown. If stack trace warnings are
    # enabled, the user's attempted password may be written in logs.
    # Also as a safety check, do not allow blank passwords.
    return unless $correct;

    my $passphrase = Crypt::Passphrase->new(
        encoder    => $self->encryption_algorithm,
        validators => $self->validator,
    );

    if ( $correct !~ /^[\${]/ ) {
        if ( $given eq $correct ) {
            if ($rehash_callback) {
                my $new_hash = $self->encrypt_password($given);
                $rehash_callback->($new_hash);
            }
            return 1;
        }
        
        return 0;
    }

    return 0 if (!$passphrase->verify_password($given, $correct));
    
    if ($passphrase->needs_rehash($correct) && $rehash_callback) {
        my $new_hash = $self->encrypt_password($given);
        $rehash_callback->($new_hash);
    }

    return 1;
}

=head2 encrypt_password $password

Encrypts password C<$password> with L</encryption_algorithm>
and returns the encrypted password.

=cut

sub encrypt_password {
    my ( $self, $password ) = @_;
    my $passphrase = Crypt::Passphrase->new(
        encoder => $self->encryption_algorithm,
    );
    return $passphrase->hash_password($password);
}

=head1 METHODS IMPLEMENTED BY PROVIDER

The following methods must be implemented by the consuming provider class.

=head2 required methods

=over

=item * authenticate_user $username, $password

If either of C<$username> or C<$password> are undefined then die.

Return true on success.

=back

=head2 optional methods

The following methods are optional and extend the functionality of the
provider.

=over

=item * get_user_details $username

Die if C<$username> is undefined. Otherwise return a user object (if
appropriate) or a hash reference of user details.

=item * get_user_roles $username

Die if C<$username> is undefined. Otherwise return an array reference of
user roles.

=item * create_user %user

Create user with fields specified in C<%user>.

Method should croak if C<username> key is empty or undefined. If a user with
the specified username already exists then we would normally expect the
method to die though this is of course dependent on the backend in use.

The new user should be returned.

=item * get_user_by_code $code

Try to find a user which has C<pw_reset_code> field set to C<$code>.

Returns the user on success.

=item * set_user_details $username, %update

Update user with C<$username> according to C<%update>.

Passing an empty or undefined C<$username> should cause the method to die.

The update user should be returned.

=item * set_user_password $username, $password

Set the password for the user specified by C<$username> to <$password>
encrypted using L</encrypt_password> or via whatever other method is
appropriate for the backend.

=item * password_expired $user

The C<$user> should be as returned from L</get_user_details>. The method
checks whether the user's password has expired and returns 1 if it has and
0 if it has not.

=back

=cut

1;

