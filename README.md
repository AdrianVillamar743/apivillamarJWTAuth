# apivillamarJWTAuth
 Api desarrollada utilizando Laravel para login y registro con uso de tokens jwt
API REST JWT Auth- LARAVEL 8 Villamar

En  esta ocasión utilizaremos Laravel 8 para crear una api rest con validación jwt para registro y login. Las herramientas a utilizarse serían en mi caso Xampp, Visual Studio y el navegador de tu preferencia.
1.- En este caso en nuestra aplicación de Xampp iremos a la ruta de C:\xampp\htdocs
2.- Escribiremos el comando 
     composer create-project laravel/laravel apivillamarJWTAuth

      Cabe destacar que apivillamarJWTAuth es el nombre que yo le puse.

3.- Probamos accediendo al proyecto por medio de la terminal.
4.- Crearemos una nueva bd llamada empresa_villamar
5.- Accederemos al archivo .env en la ruta de C:\xampp\htdocs\proyectos\apivillamarJWTAuth\.env
6.- Colocamos el nombre de la base de datos en DB_USERBAME=empresa_villamar
Quedando de la siguiente manera.

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=empresa_villamar
DB_USERNAME=root
DB_PASSWORD=

7.- Abrimos el archivo AppServiceProvider en la ruta de 
C:\xampp\htdocs\proyectos\apivillamarJWTAuth\app\Providers\AppServiceProvider.php

Configuramos los schemas de Facades.

use Illuminate\Support\Facades\Schema;

Y modificamos la función boot para no tener problemas de migraciones.

    public function boot()
    {
        Schema::defaultStringLength(191);
    }

8.- Migramos a la base de datos con el comando

php artisan migrate

9.- Instalaremos una librería de jwt vía composer con el comando

composer require tymon/jwt-auth

10.- Nos dirigiremos al archivo de app.php en la ruta de
C:\xampp\htdocs\proyectos\apivillamarJWTAuth\config\app.php
Para agregar en caso de no tener la siguiente libreria

Tymon\JWTAuth\Providers\LaravelServiceProvider::class,

En el apartado de 
        /*
         * Application Service Providers...
         */

11.- Publicaremos el paquete de configuración con el comando

php artisan vendor:publish

Y seleccionamos el indice que tenga a 

Provider: Tymon\JWTAuth\Providers\LaravelServiceProvider'
En este caso fue 10

12.- Debemos generar una clave secreto utilizando el comando

php artisan jwt:secret

13.- Verificamos que en el archivo .env se ha creado una variable llamada JWT_SECRET.


14.- Nos dirigiremos a la ruta 
C:\xampp\htdocs\proyectos\apivillamarJWTAuth\config\auth.php para modificar el archivo auth.php

    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],



'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
Claro buscamos los arrays de existir los modificamos o sobreescribimos o agregamos.


15.- Nos dirigiremos al archivo User.php en la ruta app/Models para modificar lo siguiente

use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject

Sí da un error de implementación pero sigamos adelante


16.- Vamos al archivo api.php ubicado en la ruta de routes\api.php

agregamos estas rutas

Route::group([

    'middleware' => 'api',
    'prefix' => 'auth'

], function ($router) {

    Route::post('login', 'App\Http\Controllers\AuthController@login');
    Route::post('logout', 'App\Http\Controllers\AuthController@logout');
    Route::post('refresh', 'App\Http\Controllers\AuthController@refresh');
    Route::post('me', 'App\Http\Controllers\AuthController@me');

});

17.- Crearemos un nuevo controlador con el comando 

php artisan make:controller AuthController

18.- Pegamos lo siguiente

<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}

19.- Importante agregar estos dos metodos en el modelo User
    public function getJWTIdentifier(){
        return $this->getKey();
    }

    public function getJWTCustomClaims(){
        return [];
    }

Para mayor info visitar el siguiente link

https://jwt-auth.readthedocs.io/en/develop/quick-start/

