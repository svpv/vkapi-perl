package Net::VKontakte::Standalone;

use 5.006000;
use strict;
use warnings;

use URI;
use WWW::Mechanize;
use JSON;
use Carp;

our $VERSION = '0.18_95';

sub import {
	my $class = shift;
	return unless @_;
	my %opts = @_;
	my @import = exists $opts{import} ? @{delete $opts{import}} : (qw/
		auth auth_uri redirected permament_token api post captcha_handler error errors_noauto access_token AUTOLOAD
	/);
	my $vk = $class->new(%opts);
	my $caller = caller;
	no strict 'refs';
	for my $method (@import) {
		*{$caller."::".$method} = sub { $vk->$method(@_) };
	};
}

sub new {
	my $class = shift;
	my $self = bless {},$class;
	$self->{browser} =  WWW::Mechanize::->new(
		agent => __PACKAGE__.$VERSION,
		autocheck => 1,
	);
	if (@_ == 1) {
		$self->{api_id} = $_[0];
	} elsif (@_ % 2 == 0) { # smells like hash
		my %opt = @_;
		for my $key (qw/api_id errors_noauto captcha_handler access_token/) {
			$self->{$key} = $opt{$key} if defined $opt{$key};
		}
	} else {
		croak "wrong number of arguments to constructor";
	}
	croak "api_id or access_token is required" unless $self->{api_id} or $self->{access_token};
	return $self;
}

sub _request {
	my ($self, $params, $base) = @_;
	(my $uri = URI::->new($base))->query_form($params);
	return $self->{browser}->get($uri);
}

sub auth { # dirty hack
	my ($self,$login,$password,$scope) = @_;
	@{$self}{"login","password","scope"} = ($login, $password, $scope); # reuse in case of reauth
	$self->{browser}->cookie_jar->clear; # VK won't give us the fields if we have authentificated cookies
	$self->{browser}->get($self->auth_uri($scope));
	$self->{browser}->submit_form(
		with_fields => {
			email => $login,
			pass => $password,
		},
	); # log in
	$self->{browser}->submit unless $self->{browser}->uri =~ m|^https://oauth.vk.com/blank.html|; # allow access if requested to
	return $self->redirected($self->{browser}->uri);
}

sub auth_uri {
	my ($self, $scope, $display) = @_;
	(my $uri = URI::->new("https://api.vkontakte.ru/oauth/authorize"))->query_form(
		{
			client_id => $self->{api_id},
			redirect_uri => "blank.html",
			scope => $scope,
			response_type => "token",
			display => $display,
		}
	);
	return $uri->canonical;
}

sub redirected {
	my ($self, $uri) = @_;
	my %params = map { split /=/,$_,2 } split /&/,$1 if $uri =~ m|https://oauth.vk.com/blank.html#(.*)|;
	croak "No access_token returned (wrong login/password?)" unless defined $params{access_token};
	$self->{access_token} = $params{access_token};
	croak "No token expiration time returned" unless $params{expires_in};
	$self->{auth_time} = time;
	$self->{expires_in} = $params{expires_in};
	return $self;
}

sub permament_token {
	my ($self, %params) = @_;
	$params{grant_type} = "password";
	$params{client_id} = $self->{api_id};
	REDO: { # for CAPTCHA
		my $result = decode_json $self->_request(\%params, "https://oauth.vk.com/token")->decoded_content;
		if ($result->{access_token}) {
			$self->{access_token} = $result->{access_token};
			return 1;
		} elsif ($result->{error}) {
			if ($result->{error} eq "need_captcha" and $self->{captcha_handler}) {
				$params{captcha_key} = $self->{captcha_handler}->($result->{error}{captcha_img});
				$params{captcha_sid} = $result->{error}{captcha_sid};
				redo REDO;
			} elsif ($self->errors_noauto) {
				$self->{error} = $result;
				if (ref $self->{errors_noauto} and ref $self->{errors_noauto} eq 'CODE') {
					$self->{errors_noauto}->($result);
				}
				return;
			} else {
				croak "Permament token call returned error ".$result->{error_description};
			}
		} else {
			croak "Permament token call didn't return response or error\n".
				$Carp::Verbose ? eval { require Data::Dumper; Data::Dumper::Dumper($result) }
				: "";
		}
	}
}

sub api {
	my ($self,$method,$params) = @_;
	croak "Cannot make API calls unless authentificated" unless defined $self->{access_token};
	if (time - $self->{auth_time} > $self->{expires_in} and $self->{login} && $self->{password} && $self->{scope}) {
		$self->auth($self->{"login","password","scope"});
	}
	$params->{access_token} = $self->{access_token};
	REQUEST: {
		my $response = decode_json $self->_request($params,"https://api.vk.com/method/$method")->decoded_content;
		if ($response->{response}) {
			return $response->{response};
		} elsif ($response->{error}) {
			if (14 == $response->{error}{error_code} and $self->{captcha_handler}) { # it's a CAPTCHA request, user wants to handle it specially
				$params->{captcha_key} = $self->{captcha_handler}->($response->{error}{captcha_img});
				$params->{captcha_sid} = $response->{error}{captcha_sid};
				redo REQUEST;
			} elsif ($self->{errors_noauto}) { # user ignores or handles errors by him(her)self, it's not a CAPTCHA or no captcha_handler
				$self->{error} = $response->{error};
				if (ref $self->{errors_noauto} and ref $self->{errors_noauto} eq "CODE") {
					$self->{errors_noauto}->($response->{error});
				}
				return;
			} else {
				if (6 == $response->{error}{error_code}) { # Too many requests per second. 
					sleep 1;
					redo REQUEST;
				} else { # other special cases which can be handled automatically?
					croak "API call returned error: ".$response->{error}{error_msg};
				}
				# 5 == user authorisation failed, invalid access token of any kind
			}
		} else {
			croak "API call didn't return response or error\n".
				$Carp::Verbose ? eval { require Data::Dumper; Data::Dumper::Dumper($response) }
				: "";
		}
	}
}

sub post {
	my ($self, $url, %fields) = @_;
	return decode_json $self->{browser}->post($url, Content_Type => 'form_data', Content => [ %fields ]);
}

sub captcha_handler {
	my ($self, $handler) = @_;
	croak "\$handler is not a subroutine reference" unless ref $handler eq "CODE";
	$self->{captcha_handler} = $handler;
	return $self;
}

sub error {
	return shift->{error};
}

sub errors_noauto {
	my ($self, $noauto) = @_;
	$self->{errors_noauto} = $noauto; # whatever this means
	return $self;
}

sub access_token {
	my ($self, $token) = @_;
	return defined $token ? do { $self->{access_token} = $token } : $self->{access_token};
}

sub DESTROY {}

sub AUTOLOAD {
	our $AUTOLOAD;
	$AUTOLOAD =~ s/.*:://;
	$AUTOLOAD =~ tr/_/./;
	my ($self, $params) = @_;
	$self->api($AUTOLOAD,$params);
}

1;
__END__

=head1 NAME

Net::VKontakte::Standalone - Perl extension for creating standalone Vkontakte API applications

=head1 SYNOPSIS

  use Net::VKontakte::Standalone;
  my $vk = new Net::VKontakte::Standalone:: "12345678";
  my $auth_uri = $vk->auth_uri("wall,messages");

  # make the user able to enter login and password at this URI
  
  $vk->redirected($where);
  $vk->api("activity.set",{text => "playing with VK API"});


=head1 DESCRIPTION

This module is just a wrapper for some JSON parsing and WWW::Mechanize magic, not much else.

=head1 CONSTRUCTOR METHODS

=over 4

=item $vk = Net::VKontakte::Standalone::->new($api_id);

=item $vk = Net::Vkontalte::Standalone::->new( key => value );

This creates the main object, sets the API ID variable (which can be got from the application
management page) and creates the WWW::Mechanize object.

Possible keys:

=over

=item api_id

API ID of the application, required unless access_token is specified.

=item access_token

A valid access_token (for example, a permament token got from persistent storage). Required unless api_id is specified.

=item errors_noauto

If true, return undef instead of automatic error handling (which includes limiting requests per second and throwing exceptions). If this is a coderef, it will be called with the {error} subhash as the only argument. In both cases the error will be stored and will be accessible via $vk->error method.

=item captcha_handler

Should be a coderef to be called upon receiving {error} requiring CAPTCHA. The coderef will be called with the CAPTCHA URL as the only argument and should return the captcha answer (decoded to characters if needed). Works even when errors_noauto is true (or a coderef).

=back

=back 

=head1 METHODS

=over

=item $vk->auth($login,$password,$scope)

This method should be called first. It uses OAuth2 to authentificate the user at the vk.com server
and accepts the specified scope (seen at L<http://vk.com/dev/permissions>).
After obtaining the access token is saved for future use.

This is not a recommended way to authentificate standalone VKontakte applications, but it works (for now). Feel
free to use it in small hacks but stay away from it in production.

=item $vk->auth_uri($scope)

This method should be called first. It returns the URI of the login page to show to the user
(developer should call a browser somehow, see L<http://vk.com/dev/auth_mobile> for more info).

The $scope parameter is described at L<http://vk.com/dev/permissions>.

=item $vk->redirected($uri)

This method should be called after a successful authorisation with the URI user was redirected
to. Then the expiration time and the access token are retreived from this URI and stored in
the $vk object.

=item $vk->permament_token(params => "values", ...);

This method provides another way of (non-interactive) authentification:

=over

=item Your application should be trusted by VK.com

=item The token is permament, it can be stored and used again

=item You should not store the login and the password

=item Required parameters are:

=over

=item client_secret

Your application's secret

=item username

User's login

=item password

User's password

=back

=item Optional parameters are:

=over

=item scope

Needed access rights, as in L<http://vk.com/dev/permissions>

=item test_redirect_uri

Set it to 1 to initiate test check of the user using redirect_uri error. Set 0 otherwise (by default).

=back

=back

Read more about permament tokens at L<http://vk.com/dev/auth_direct>.

This method respects captcha_handler and errors_noauto parameters of the $vk object.

=item $vk->api($method,{parameter => "value", parameter => "value" ...})

This method calls the API methods on the server, as described on L<http://vk.com/dev/api_requests>.
Resulting JSON is parsed and returned as a hash reference.

=item $vk->post($url, parameter => "value", file_parameter => [$filename, ...], ... )

This method makes uploading files (see L<http://vk.com/dev/upload_files>) a lot easier.

Firstly, get the upload URI using the respective API method. Secondly, use this method to upload the file (NOTE: no return value error checking is done because return values are not consistent between different uploads). Finally, pass the gathered data structure to the another API method which completes your upload.

HTTP::Request::Common is used to build the POST request. Read its manual page for more info on uploading files (only filename parameter is usually required).

=item $vk->captcha_handler($sub)

Sets the sub to call when CAPTCHA needs to be entered. Works even when errors_noauto is true.

=item $vk->error

Returns the last {error} subhash received (if errors_nonfatal is true).

=item $vk->errors_noauto

If true, return undef instead of automatic API error handling . If this is a coderef, it will be called with the {error} subhash as the only argument. In both cases the error will be stored and will be accessible via $vk->error method.

=item $vk->access_token($token)

This method returns the access_token of your $vk object and sets it (if defined), allowing you to save your permament access token and use it later (when your application restarts).

=back 

=head1 AUTOLOADING

Instead of calling $vk->api(...) you can substitute the "."'s by "_"'s in the API method name and call this method on an object instead. For example,

    $vk->api("wall.post", {message => "Hello, world!"});

should be equivalent to

    $vk->wall_post({message => "Hello, world!"});

=head1 EXPORTS

None by default.

You can pass the constructor arguments to 'use Net::VKontakte::Standalone' (only hash constructor form is supported). This way it will create the $vk object for you, set up the wrappers around its methods and export them to your program (all by default). You can pass an optional parameter 'import' which should be an array reference with the list of method wrappers you need to import.

This can be useful in very small scripts or one-liners. For example,

    use Net::VKontakte::Standalone (access_token => "whatever", import => ['AUTOLOAD']);
    activity_set({text => "playing with VK API"});

=head1 BUGS

Probably many. Feel free to report my mistakes and propose changes.

Currently there is no test suite, and some features were not tested at all.

=head1 SEE ALSO

L<https://vk.com/dev> for the list of methods and how to use them.

=head1 AUTHOR

Krylov Ivan, E<lt>krylov.r00t@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Krylov Ivan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
