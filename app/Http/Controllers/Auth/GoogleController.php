<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Google\Exception;
use Google\Service\Gmail;
use Illuminate\Foundation\Application;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class GoogleController extends Controller
{
    /** Авторизация через google OAuth */
    public function login(Request $request): Application|Redirector|RedirectResponse
    {
        if (isset($_GET['code'])) {
            $client = new \Google\Client();
            $client->setAuthConfig('../google.json');
            $client->addScope(Gmail::MAIL_GOOGLE_COM);
            $token = $client->fetchAccessTokenWithAuthCode($_GET['code']);
            if (!$token) {
                throw new Exception('Ошибка авторизации в сервисе google');
            }

            $service = new Gmail($client);
            $profile = $service->users->getProfile('me');
            $userEmail = $profile->emailAddress;

            $user = User::query()
                ->where('email', $userEmail)
                ->first();

            if (!$user) {
                User::query()->create([
                    'name' => $userEmail,
                    'email' => $userEmail,
                    'password' => Hash::make($userEmail)
                ]);
            }

            Auth::login($user);
        }

        return redirect(route('dashboard'));
    }

    /** Создаёт ссылку для авторизации пользователя и перенаправляет пользователя по ней */
    public function getAccessToken(Request $request): Application|Redirector|RedirectResponse
    {
        $client = new \Google\Client();
        $client->setAuthConfig('../google.json');
        $client->addScope(Gmail::MAIL_GOOGLE_COM);
        $redirect_uri = 'http://localhost/google-login';
        $client->setRedirectUri($redirect_uri);

        return redirect($client->createAuthUrl(Gmail::MAIL_GOOGLE_COM));
    }
}
