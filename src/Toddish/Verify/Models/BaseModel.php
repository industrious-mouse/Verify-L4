<?php
namespace Toddish\Verify\Models;

use Config;
use Illuminate\Database\Eloquent\Model as Eloquent;

class BaseModel extends Eloquent
{
	/**
	 * Table prefix
	 *
	 * @var string
	 */
	protected $prefix = '';

	/**
	 * Create a new Eloquent model instance.
	 *
	 * @param  array $attributes
	 */
	public function __construct(array $attributes = array())
	{
		parent::__construct($attributes);

		$this->attributes = $attributes;

		// Set the prefix
		$this->prefix = config('verify.prefix');

		$this->table = $this->prefix.$this->getTable();
	}
}
