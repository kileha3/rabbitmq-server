%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2023 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(oauth_provider_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("amqp_client/include/amqp_client.hrl").
-include_lib("eunit/include/eunit.hrl").

-import(rabbit_ct_client_helpers, [close_connection/1, close_channel/1,
                                   open_unmanaged_connection/4, open_unmanaged_connection/5,
                                   close_connection_and_channel/2]).
-import(rabbit_mgmt_test_util, [amqp_port/1]).

all() ->
    [
     {group, happy_path}
%     ,{group, unhappy_path}
%     ,{group, unvalidated_jwks_server}
%     ,{group, no_peer_verification}
    ].

groups() ->
    [
     {happy_path, [], [
                       test_successful_connection
                      ]
     }

    ].

%%
%% Setup and Teardown
%%

-define(UTIL_MOD, rabbit_auth_backend_oauth2_test_util).
-define(RESOURCE_SERVER_ID, <<"rabbitmq">>).
-define(RESOURCE_SERVER_TYPE, <<"rabbitmq">>).
-define(OAUTH_PROVIDER_ID, <<"uaa">>).
-define(EXTRA_SCOPES_SOURCE, <<"additional_rabbitmq_scopes">>).

init_per_suite(Config) ->
    rabbit_ct_helpers:log_environment(),
    rabbit_ct_helpers:run_setup_steps(Config,
      rabbit_ct_broker_helpers:setup_steps() ++ [
        fun preconfigure_node/1,
        fun start_jwks_server/1,
        fun preconfigure_token/1
      ]).

end_per_suite(Config) ->
    rabbit_ct_helpers:run_teardown_steps(Config,
      [
        fun stop_jwks_server/1
      ] ++ rabbit_ct_broker_helpers:teardown_steps()).

init_per_group(happy_path, Config) ->
    add_vhosts(Config);

init_per_group(_Group, Config) ->
    add_vhosts(Config),
    Config.

end_per_group(_Group, Config) ->
    delete_vhosts(Config),
    Config.

add_vhosts(Config) ->
    %% The broker is managed by {init,end}_per_testcase().
    lists:foreach(fun(Value) -> rabbit_ct_broker_helpers:add_vhost(Config, Value) end,
                  [<<"vhost1">>, <<"vhost2">>, <<"vhost3">>, <<"vhost4">>]).

delete_vhosts(Config) ->
    %% The broker is managed by {init,end}_per_testcase().
    lists:foreach(fun(Value) -> rabbit_ct_broker_helpers:delete_vhost(Config, Value) end,
                  [<<"vhost1">>, <<"vhost2">>, <<"vhost3">>, <<"vhost4">>]).


preconfigure_node(Config) ->
    ok = rabbit_ct_broker_helpers:rpc(Config, 0, application, set_env,
                                      [rabbit, auth_backends, [rabbit_auth_backend_oauth2]]),
    ok = rabbit_ct_broker_helpers:rpc(Config, 0, application, set_env,
                                      [rabbitmq_auth_backend_oauth2, resource_server_id, ?RESOURCE_SERVER_ID]),

    Config.

start_jwks_server(Config) ->
    Jwk   = ?UTIL_MOD:fixture_jwk(),
    %% Assume we don't have more than 100 ports allocated for tests
    PortBase = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_ports_base),
    JwksServerPort = PortBase + 100,

    %% Both URLs direct to the same JWKS server
    %% The NonStrictJwksUrl identity cannot be validated while StrictJwksUrl identity can be validated
    Issuer = "https://localhost:" ++ integer_to_list(JwksServerPort),
    JwksUrl = Issuer ++ "/jwks",

    ok = application:set_env(jwks_http, keys, [Jwk]),
    ok = application:set_env(jwks_http, openid_config, #{
      "issuer" => Issuer,
      "jwks_uri" => JwksUrl
    }),

    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(cowboy),
    CertsDir = ?config(rmq_certsdir, Config),
    ok = jwks_http_app:start(JwksServerPort, CertsDir),

    OauthProviders =
      #{ ?OAUTH_PROVIDER_ID => [
        {issuer, Issuer},
        {ssl_options, [
            {verify, verify_peer},
            {cacertfile, filename:join([CertsDir, "testca", "cacert.pem"])}
          ]}
      ]},

    ok = rabbit_ct_broker_helpers:rpc(Config, 0, application, set_env,
                                [rabbitmq_auth_backend_oauth2, oauth_providers, OauthProviders]),
    ok = rabbit_ct_broker_helpers:rpc(Config, 0, application, set_env,
                                [rabbitmq_auth_backend_oauth2, oauth_provider_id, ?OAUTH_PROVIDER_ID]),
    rabbit_ct_helpers:set_config(Config,
                                 [
                                  {jwks_url, JwksUrl},
                                  {fixture_jwk, Jwk}]).

stop_jwks_server(Config) ->
    ok = jwks_http_app:stop(),
    Config.

generate_valid_token(Config) ->
    generate_valid_token(Config, ?UTIL_MOD:full_permission_scopes()).

generate_valid_token(Config, Scopes) ->
    generate_valid_token(Config, Scopes, undefined).

generate_valid_token(Config, Scopes, Audience) ->
    Jwk = case rabbit_ct_helpers:get_config(Config, fixture_jwk) of
              undefined -> ?UTIL_MOD:fixture_jwk();
              Value     -> Value
          end,
    Token = case Audience of
        undefined -> ?UTIL_MOD:fixture_token_with_scopes(Scopes);
        DefinedAudience -> maps:put(<<"aud">>, DefinedAudience, ?UTIL_MOD:fixture_token_with_scopes(Scopes))
    end,
    ?UTIL_MOD:sign_token_hs(Token, Jwk).

generate_valid_token_with_extra_fields(Config, ExtraFields) ->
    Jwk = case rabbit_ct_helpers:get_config(Config, fixture_jwk) of
              undefined -> ?UTIL_MOD:fixture_jwk();
              Value     -> Value
          end,
    Token = maps:merge(?UTIL_MOD:fixture_token_with_scopes([]), ExtraFields),
    ?UTIL_MOD:sign_token_hs(Token, Jwk).

generate_expired_token(Config) ->
    generate_expired_token(Config, ?UTIL_MOD:full_permission_scopes()).

generate_expired_token(Config, Scopes) ->
    Jwk = case rabbit_ct_helpers:get_config(Config, fixture_jwk) of
              undefined -> ?UTIL_MOD:fixture_jwk();
              Value     -> Value
          end,
    ?UTIL_MOD:sign_token_hs(?UTIL_MOD:expired_token_with_scopes(Scopes), Jwk).

generate_expirable_token(Config, Seconds) ->
    generate_expirable_token(Config, ?UTIL_MOD:full_permission_scopes(), Seconds).

generate_expirable_token(Config, Scopes, Seconds) ->
    Jwk = case rabbit_ct_helpers:get_config(Config, fixture_jwk) of
              undefined -> ?UTIL_MOD:fixture_jwk();
              Value     -> Value
          end,
    Expiration = os:system_time(seconds) + Seconds,
    ?UTIL_MOD:sign_token_hs(?UTIL_MOD:token_with_scopes_and_expiration(Scopes, Expiration), Jwk).

preconfigure_token(Config) ->
    Token = generate_valid_token(Config),
    rabbit_ct_helpers:set_config(Config, {fixture_jwt, Token}).

%%
%% Test Cases
%%

test_successful_connection(Config) ->
    {_Algo, Token} = rabbit_ct_helpers:get_config(Config, fixture_jwt),
    Conn     = open_unmanaged_connection(Config, 0, <<"username">>, Token),
    {ok, Ch} = amqp_connection:open_channel(Conn),
    #'queue.declare_ok'{queue = _} =
        amqp_channel:call(Ch, #'queue.declare'{exclusive = true}),
    close_connection_and_channel(Conn, Ch).
