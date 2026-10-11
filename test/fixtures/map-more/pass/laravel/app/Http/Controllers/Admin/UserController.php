<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function role(Request $request, User $user)
    {
        $role = $request->validate(['role' => 'in:member,admin'])['role'];
        $user->update(['role' => $role]);
        AuditLog::create(['actor_id' => $request->user()->id, 'action' => 'set_role', 'target_id' => $user->id]);

        return response()->noContent();
    }
}
