<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function role(Request $request, User $user)
    {
        $user->update(['role' => $request->input('role')]);

        return response()->noContent();
    }
}
