<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate(['email' => 'required|email', 'password' => 'required']);
        $user = User::where('email', $data['email'])->first();
        if ($user && Hash::check($data['password'], $user->password)) {
            $next = (string) $request->query('next');

            return redirect(str_starts_with($next, '/') && ! str_starts_with($next, '//') ? $next : '/');
        }
        abort(401);
    }
}
