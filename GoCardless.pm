package GoCardless;

=head1 NAME

GoCardless

=head1 DESCRIPTION

GoCardless Perl client library.  

This module gets GoCardless account details from GoCardless::Config

All methods are class methods.

=head1 AUTHOR INFORMATION and COPYRIGHT

This library was written by Mythic Beasts Ltd. (http://www.mythic-beasts.com).

It has been placed into the Public Domain: do with it as you see fit, although
an attribution in any derivative work would be appreciated.

=head1 METHODS 

=over 4

=cut

use GoCardless::Config;
use LWP::UserAgent;
use LWP;
use Digest::SHA qw(hmac_sha256_hex);
use POSIX qw(strftime);
use Data::Dumper;
use JSON;
use MIME::Base64;

use strict;

sub rfc5849_encode {
    my $s = shift;
    $s =~ s#([^-.~_a-z0-9])#sprintf('%%%02X', ord($1))#gei;
    return $s;
}

sub flatten_param { 
    my($k, $v) = @_;
    my @r;
    if(ref $v eq 'HASH') {
        foreach my $kk (keys %$v) {
            push @r, flatten_param("$k\[$kk\]", $v->{$kk});
        } 
    }
    elsif(ref $v eq 'ARRAY') {
        foreach my $kk (@$v) {
            push @r, flatten_param("$k\[\]", $kk);
        } 

    }
    else {
        push @r, ($k, $v);
    }
    return @r;
}

=item signature [ PARAM_HASHREF ]

Generates a signature for the supplied hash of parameters, following the
normalisation and signature process described here:

  https://developer.gocardless.com/#signing-requests

Returns a string containing the signature.

=cut

sub signature($) {
    my($params) = @_;

    $params = { map { flatten_param($_, $params->{$_}) } keys %$params };
    $params = { map { rfc5849_encode($_) => rfc5849_encode($params->{$_}) } keys %$params };

    my $s = join '&', map { $_ . '=' . $params->{$_}   } sort { $a cmp $b || $params->{$a} cmp $params->{$b} }  keys %$params;
    my $sig = hmac_sha256_hex($s, $GoCardless::Config::app_secret);
    return $sig;
}

sub nonce {
    my $id = '';
    for (my $i = 0; $i < 32; $i++) {
        $id .= sprintf('%x',rand() * 16);
    }
    return $id;
}

sub query_string {
    my($r) = @_;
    return join '&', map { rfc5849_encode($_) . '='. rfc5849_encode($r->{$_}) } keys %$r;
}

=item check_signature [ PARAM_HASHREF ]

Checks that the signature in the supplied hash of parameters is valid.  The
supplied PARAM_HASHREF should include a member called "signature".

=cut
sub check_signature($) {
    my($p) = @_;
    $p = {%$p};
    my $sig = $p->{signature};
    delete $p->{signature};
    return $sig eq signature($p);
}

=item create_preauth [ ACCOUNT, NAME, DESCRIPTION, AMOUNT ]

Creates a pre-authorisation.  ACCOUNT is a Mythic Beasts account object - this
will need to be modified by users of this module.

NAME and DESCRIPTION will contain the name and description for the Direct Debit
to be presented to the user.

AMOUNT is the maximum amount to be taken per month under this pre-auth.
Frequency of DDs is hard-coded to once-per-month.

Returns a URL to direct the user to to create the pre-auth.

=cut
sub create_preauth {
    my($account, $name, $description, $amount) = @_;
    my $r = {
        'pre_authorization[max_amount]' => $amount,
        'pre_authorization[amount]' => $amount,
        'pre_authorization[interval_length]' => 1,
        'pre_authorization[interval_unit]' => 'month',
        'pre_authorization[merchant_id]' => $GoCardless::Config::merchant_id,
        'pre_authorization[name]' => $name,
        'pre_authorization[description]' => $description,
        'pre_authorization[calendar_intervals]' => 'true',
        'pre_authorization[user][account_holder_name]' => $account->get_field('admin_org') || $account->fullname(),
        'pre_authorization[user][billing_email]' => $account->billing_email(),
        'pre_authorization[user][billing_address1]' => $account->get_field('billing_add1'),
        'pre_authorization[user][billing_address2]' => $account->get_field('billing_add2'),
        'pre_authorization[user][billing_town]' => $account->get_field('billing_city'),
        'pre_authorization[user][billing_postcode]' => $account->get_field('billing_postcode'),
        nonce => nonce(),
        client_id => $GoCardless::Config::client_id,
        timestamp => strftime('%Y-%m-%dT%H:%M:%S%z',localtime(time)),
        state => $account->id(),
    };
    $r->{signature} = GoCardless::signature($r);
    return $GoCardless::Config::api_url . '/connect/pre_authorizations/new?' . query_string($r);
}

sub do_post($$;$) {
    my($url_part, $p, $basic_auth) = @_;
    $p = {%$p};
    #$p->{signature} = signature($p);
    my $ua = LWP::UserAgent->new;

    my $url = $GoCardless::Config::api_url . $url_part;

    my $req = new HTTP::Request('POST', $url );

    $req->header(Accept => 'application/json');
    $req->header('Content-Type' => 'application/json');
    if($basic_auth) {
        $req->header('Authorization' => 'Basic '.encode_base64($GoCardless::Config::client_id . ':'. $GoCardless::Config::app_secret,''));
    }
    else {
        $req->header(Authorization => 'bearer '.$GoCardless::Config::merchant_access_token);
    }
    $req->content(to_json($p));

    my $res = $ua->request($req);

    if($res->is_success) {
        return [1, from_json($res->content)];
    }
    else {
        return [0, $res->content];
    }
}

sub do_get($;$) {
    my($url_part,$basic_auth) = @_;
    my $ua = LWP::UserAgent->new;

    my $url = $GoCardless::Config::api_url . $url_part;

    my $req = new HTTP::Request('GET', $url );

    $req->header(Accept => 'application/json');
    if($basic_auth) {
        $req->header('Authorization' => 'Basic '.encode_base64($GoCardless::Config::client_id . ':'. $GoCardless::Config::app_secret,''));
    }
    else {
        $req->header(Authorization => 'bearer '.$GoCardless::Config::merchant_access_token);
    }

    my $res = $ua->request($req);

    if($res->is_success) {
        return [1, from_json($res->content)];
    }
    else {
        return [0, $res->content];
    }
}


=item confirm_preauth [ RESOURCE_ID ]

Confirms the pre-authorisation identified by RESOURCE_ID

Returns an arrayref of [ status, message ].  Status == 1 => success, status == 0 => failure

=cut

sub confirm_preauth($) {
    my($rid) = @_;
    return do_post('/api/v1/confirm', { resource_type => 'pre_authorization', resource_id => $rid }, 1);
}

=item bill_under_preauth [ PREAUTH_ID, AMOUNT, DESCRIPTION ]

Creates a bill under the pre-authorisation identified by PREAUTH_ID, for the AMOUNT specified.

Returns an arrayref of [ status, message ].  Status == 1 => success, status == 0 => failure

=cut
sub bill_under_preauth($$$) {
    my($pid, $amount, $description) = @_;
    return do_post('/api/v1/bills', { bill => {amount => $amount, pre_authorization_id => $pid, description => $description }});
}

=item get_bill [ BILL_ID ]

Retrieves the bill identified by BILL_ID

Returns an arrayref of [ status, message ].  Status == 1 => success, status == 0 => failure

In the case of success, message will be a Perl data structure representing the bill.

=cut
sub get_bill($) {
    my($bill_id) = @_;
    return do_get('/api/v1/bills/'.$bill_id);
}

1;
