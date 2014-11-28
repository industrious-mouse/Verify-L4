<?php
namespace Toddish\Verify;

use Illuminate\Auth\UserProviderInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\User as UserContract;

class VerifyUserProvider implements UserProviderInterface
{
    /**
     * The hasher implementation.
     *
     * @var \Illuminate\Contracts\Hashing\Hasher
     */
    protected $hasher;

    /**
     * The Eloquent user model.
     *
     * @var string
     */
    protected $model;

	/**
	 * Create a new database user provider.
	 *
	 * @param HasherContract 		$hasher
	 * @param string				$model
	 */
    public function __construct(HasherContract $hasher, $model)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }

	/**
	 * Retrieve a user by their unique identifier.
	 *
	 * @param  mixed $identifier
	 *
	 * @return \Illuminate\Contracts\Auth\User|null
	 */
    public function retrieveByID($identifier)
    {
        return $this->createModel()->newQuery()->find($identifier);
    }

	/**
	 * Retrieve a user by the given credentials.
	 *
	 * @param  array $credentials
	 *
	 * @throws UserNotFoundException
	 * @return \Illuminate\Contracts\Auth\User|null
	 */
    public function retrieveByCredentials(array $credentials)
    {
        // Are we checking by identifier?
        if (array_key_exists('identifier', $credentials)) {

            // Grab each val to be identifed against
            foreach (\Config::get('verify::identified_by') as $identified_by) {
                // Create a new query for each check
                $query = $this->createModel()->newQuery();
                // Start off the query with the first identified_by value
                $query->where($identified_by, $credentials['identifier']);

                // Add any other values to user has passed in
                foreach ($credentials as $key => $value) {
                    if (
                        !str_contains($key, 'password') &&
                        !str_contains($key, 'identifier')
                    ) {
                        $query->where($key, $value);
                    }
                }

                if ($query->count() != 0) {
                    break;
                }
            }
        }
        else
        {
            // First we will add each credential element to the query as a where clause.
            // Then we can execute the query and, if we found a user, return it in a
            // Eloquent User "model" that will be utilized by the Guard instances.
            $query = $this->createModel()->newQuery();

            foreach ($credentials as $key => $value) {
                if (!str_contains($key, 'password')) {
                    $query->where($key, $value);
                }
            }
        }

        // Failed to find a user?
        if ($query->count() == 0) {
            throw new UserNotFoundException('User can not be found');
        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param 	Authenticatable         $user
     * @param	array					$credentials
     * @throws  UserDeletedException
     * @throws  UserDisabledException
     * @throws  UserPasswordIncorrectException
     * @throws  UserUnverifiedException
     * @return  bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        $plain = $credentials['password'];
        // Is user password is valid?
        if(!$this->hasher->check($user->salt.$plain, $user->getAuthPassword())) {
            throw new UserPasswordIncorrectException('User password is incorrect');
        }

        // Valid user, but are they verified?
        if (!$user->verified) {
            throw new UserUnverifiedException('User is unverified');
        }

        // Is the user disabled?
        if ($user->disabled) {
            throw new UserDisabledException('User is disabled');
        }

        // Is the user deleted?
        if ($user->deleted_at !== NULL) {
            throw new UserDeletedException('User is deleted');
        }

        return true;
    }

    /**
     * Create a new instance of the model.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function createModel()
    {
        $class = '\\'.ltrim($this->model, '\\');
	
	// @todo Fix this.
        $object = new $class([]);

        if ( is_a( $object, '\Illuminate\Support\Facades\Facade' ) )
        {
            $object = $object->getFacadeRoot();
        }

        return $object;
    }

    /**
     * Retrieve a user by by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();

        return $model->newQuery()
                        ->where($model->getKeyName(), $identifier)
                        ->where($model->getRememberTokenName(), $token)
                        ->first();
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param 	Authenticatable 		$user
     * @param  	string 					$token
     *
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        $user->setRememberToken($token);

        $user->save();
    }
}

class UserNotFoundException extends \Exception {};
class UserUnverifiedException extends \Exception {};
class UserDisabledException extends \Exception {};
class UserDeletedException extends \Exception {};
class UserPasswordIncorrectException extends \Exception {};