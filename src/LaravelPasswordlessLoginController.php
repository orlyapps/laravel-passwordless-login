<?php

namespace Grosv\LaravelPasswordlessLogin;

use Grosv\LaravelPasswordlessLogin\Exceptions\ExpiredSignatureException;
use Grosv\LaravelPasswordlessLogin\Exceptions\InvalidSignatureException;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Support\Facades\Auth;

class LaravelPasswordlessLoginController extends Controller
{
    /**
     * @var PasswordlessLoginService
     */
    private $passwordlessLoginService;

    /**
     * @var UrlGenerator
     */
    private $urlGenerator;

    /**
     * LaravelPasswordlessLoginController constructor.
     *
     * @param PasswordlessLoginService $passwordlessLoginService
     */
    public function __construct(UrlGenerator $urlGenerator)
    {
        $this->urlGenerator = $urlGenerator;
    }

    /**
     * Handles login from the signed route.
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector
     * @throws \Psr\SimpleCache\InvalidArgumentException|InvalidSignatureException|ExpiredSignatureException
     */
    public function login(Request $request, PasswordlessLoginService $passwordlessLoginService)
    {
        $this->passwordlessLoginService = $passwordlessLoginService;

        if (! $this->urlGenerator->hasCorrectSignature($request) ||
            ($this->urlGenerator->signatureHasNotExpired($request) && ! $this->passwordlessLoginService->requestIsNew())) {
            throw new InvalidSignatureException();
        } elseif (! $this->urlGenerator->signatureHasNotExpired($request)) {
            throw new ExpiredSignatureException();
        }

        $this->passwordlessLoginService->cacheRequest($request);

        $user = $this->passwordlessLoginService->user;

        $guard = $user->guard_name ?? config('laravel-passwordless-login.user_guard');

        $rememberLogin = $user->should_remember_login ?? config('laravel-passwordless-login.remember_login');

        $redirectUrl = $user->redirect_url ?? ($request->redirect_to ?: config('laravel-passwordless-login.redirect_on_success'));

        if (method_exists(Auth::guard($guard), 'login')) {
            Auth::guard($guard)->login($user, $rememberLogin);

            abort_unless($user == Auth::guard($guard)->user(), 401);
        }

        return $user->guard_name ? $user->onPasswordlessLoginSuccess($request) : redirect($redirectUrl);
    }

    /**
     * Redirect testing.
     *
     * @return \Illuminate\Http\Response
     */
    public function redirectTestRoute()
    {
        return response(Auth::user()->name, 200);
    }

    /**
     * Redirect override testing.
     *
     * @return \Illuminate\Http\Response
     */
    public function overrideTestRoute()
    {
        return response('Redirected '.Auth::user()->name, 200);
    }
}
