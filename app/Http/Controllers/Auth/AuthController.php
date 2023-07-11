<?php
namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'employee_id' => 'required|string',
//            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only('employee_id', 'password');

        $token = Auth::attempt($credentials);
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = Auth::user();
        $user->avatar = get_gravatar($user->email);
        return response()->json([
            'status' => 'success',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }


    public function register(Request $request)
    {
        $request->validate([
            'employee_id' => 'required|string|max:255|unique:users',
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        try {
            $user = User::create([
                'employee_id' => $request->employee_id,
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            return response()->json($user);
        } catch (\Throwable $th) {
            return returnBack($th);
        }
    }

    public function logout()
    {
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function passwordSet(Request $request)
    {
        $request->validate([
            'new_password' => 'required|string|min:6',
        ]);
        Auth::user()->update(["password" => Hash::make($request->new_password)]);
        Auth::logout();
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully password changed. Please login again.',
        ]);
    }

    public function allUsers($dataPerPage = 10)
    {
        try {
            $users = User::paginate($dataPerPage);
            return response()->json($users);
        } catch (\Throwable $th) {
            return returnBack($th);
        }
    }

    public function searchUser(Request $request)
    {
        try {
            if($request->search){
                if(User::where("name", $request->search)->count()) {
                    return response()->json(User::where("name", $request->search)->get());
                } elseif (User::where("employee_id", $request->search)->count()) {
                    return response()->json(User::where("employee_id", $request->search)->get());
                } elseif (User::where("email", $request->search)->count()) {
                    return response()->json(User::where("email", $request->search)->get());
                } else {
                    return response()->json([]);
                }
            }else {
                return response()->json(User::all());
            }
        } catch (\Throwable $th) {
            return returnBack($th);
        }
    }
}
