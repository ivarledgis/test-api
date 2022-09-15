<?php

namespace App\Http\Controllers\api\v1;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{

    /**
     * Returns all the user
     */
    public function index(){
        try {
            $users = User::all();
            return response(['users' => $users, 'status' => 200]);

        } catch (Exception $e) {
            return response(['message' => $e->message, 'status' => 400]);
        }

    }

    /**
     * Logs in the user
     */
    public function login(Request $request){

        $login = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        if(!Auth::attempt( $login )){
            return response(['message' => 'Invalid Login Credentials', 'status' => 400]);

        }

        $accessToken  = Auth::user()->createToken('authToken')->accessToken;

        return response(['user' => Auth::user(), 'access_token' => $accessToken]);

    }


    /**
     * Registers the user
     */
    public function register(Request $request){
        $register = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
            'name' => 'required'
        ]);

        try {
            $user = User::create($register);
            $accessToken  = $user->createToken('authToken')->accessToken;
        } catch (Exception $e) {
            return response(['message' => 'Problem Creating User', 'status' => 400]);
        }
        return response(['message' => 'User Created Successfully', 'user' => $accessToken, 'status' => 200]);

    }
}
