<?php declare(strict_types=1);

namespace GeekJOB;


/**
 *
 */
enum WorkStatus
{
	case Debug;
	case Test;
	case Production;
}


/**
 * Node.js epress-session compatible handler
 *
 * Created by PhpStorm.
 * User: Alexander Mayorov <major@geekjob.ru>
 * Date: 2019-08-09
 * Time: 06:42
 */
class ExpressjsSessionHandler extends \SessionHandler
{
    /**
     * @var string
     */
	#[\Assert\All(
		new \Assert\NotNull,
		new \Assert\Length(min: 24))
	]
	private string $secret;

	/**
	 *
	 */
	final public const MDBG = WorkStatus::Production;

	/**
	 * @var object
	 */
	public readonly object $store;

    /**
     * @param array $cfg
     * @return ExpressjsSessionHandler
     */
    public static function register(array $cfg): self
    {
        //ini_set('session.name', $cfg['name']);
        if (!empty($cfg['name'])) session_name($cfg['name']);

        $session_name = session_name();

        // Session cookie exists
        if (isset($_COOKIE[$session_name])) {
            // If enabled secure mode, session ID checks on valid
            if (true === $cfg['secure'] && self::sid_tampered($_COOKIE[$session_name], $cfg['secret']))
                // If tampered - delete session cookie and generate new session ID
                unset($_COOKIE[$session_name]);;
        }

        // Create session handler object and register
        return (new self($cfg))();
    }

    /**
     * Constructor
     *
	 * @param array $config
	 * @throws \Exception
	 */
    public function __construct(private array $config)
    {
        // Set session cookie settings
        if (!empty($config['cookie'])) {
			$config['cookie']['maxage'] = (int)$config['cookie']['maxage'];

            session_set_cookie_params(
				$config['cookie']['maxage'],
				$config['cookie']['path'],
				$config['cookie']['domain'],
				$config['cookie']['secure'] ?? true,
				$config['cookie']['httpOnly'] ?? true
            );

            if (empty($config['cookie']['expires']))
				$config['cookie']['expires'] = str_replace(
                    '+00:00',
                    'Z',
                    gmdate('c', time() + $config['cookie']['maxage'])
                );
        }

        // Configure storage.
        // A common method of storing sessions is the Radish database.
        // These settings can be made in php.ini for the production version
        if (!empty($config['store'])) {
            ini_set('session.save_handler', $config['store']['handler']);
            $save_path = $config['store']['path'];
            switch ($config['store']['handler'])
			{
				case 'dragonfly':
                case 'redis':
                    if (!empty($config['store']['prefix']))
                        $save_path .= "?prefix={$config['store']['prefix']}";
                    break;

                case 'mongo':
					throw new \Exception('Driver for Mongo coming soon :)');

				default:
					throw new \Exception("Driver for {$config['store']['handler']} not implemented!");
            }

            ini_set('session.save_path', $save_path);
            ini_set('session.serialize_handler', 'php_serialize');

            if ($config['store']['ttl'] > 0)
                ini_set('session.gc_maxlifetime', (string)$config['store']['ttl']);
            if (isset($config['cookie']['maxage']))
                ini_set('session.cookie_lifetime', (string)$config['cookie']['maxage']);
        }

        $this->secret = (string)$config['secret'];
    }

    /**
     * Register session handler object.
     * @return $this
     */
    public function __invoke(): self
    {
        session_set_save_handler($this, true);
        session_start();
        $this->register_session_cookie();
        return $this;
    }

    /**
     * Read session data
     * @link https://php.net/manual/en/sessionhandlerinterface.read.php
     * @param string $id The session id to read data for.
     * @return string <p>
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function read(string $id): string
    {
		$str = parent::read($this->idmutator($id));
		if (!is_string($str))
			throw new \Exception('Session handler not work well, check connection to session storage!');

        return serialize(json_decode($str, true));
    }

    /**
     * Write session data
     * @link https://php.net/manual/en/sessionhandlerinterface.write.php
     * @param string $id The session id.
     * @param string $data <p>
     * The encoded session data. This data is the
     * result of the PHP internally encoding
     * the $_SESSION superglobal to a serialized
     * string and passing it as this parameter.
     * Please note sessions use an alternative serialization method.
     * </p>
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function write(string $id, string $data): bool
    {
        return parent::write(
            $this->idmutator($id),
            json_encode(unserialize($data))
        );
    }

    /**
     * Generate session ID compatible with node.js express-session
     *
     * @return string
     */
    public function create_sid(): string
    {
        $sid = parent::create_sid();
        $hmac =
            str_replace('=', '',
                base64_encode(
                    hash_hmac('sha256', $sid, $this->secret, true)
                )
            );
        return "s:$sid.$hmac";
    }

    /**
     * Transforms the session ID that is stored on `$_COOKIE` into the ID used on data base
     *
     * @param string $id The session ID that is stored on cookie.
     * @return string
     */
    private function idmutator(string $id): string
    {
        if (preg_match('~^s:(.*?)\.~', $id, $a)) $id = $a[1];
        return $id;
    }

    /**
     * @param string $id
     * @param string $signature
     * @return bool
     */
    public static function sid_tampered(string $id, string $secret): bool
    {
        $signature = null;
        if (preg_match('~^s:(.*?)\.(.*)$~', $id, $a)) {
            $id = $a[1];
            $signature = $a[2];
        }
        return $signature !==
            str_replace(
                '=', '',
                base64_encode(
                    hash_hmac('sha256', $id, $secret, true)
                )
            );
    }

    /**
     * Add the session cookie metadata that express-session requires.
     *
     * Warning! If this block doesn't work, the Node.js application will fail with an error:
     *
     *   node_modules/express-session/session/store.js:87
     *   var expires = sess.cookie.expires
     *                            ^
     *   TypeError: Cannot read property 'expires' of undefined
     *   at RedisStore.Store.createSession (node_modules/express-session/session/store.js:87:29)
     *   at node_modules/express-session/index.js:478:15
     *
     * @return void
     */
    public function register_session_cookie(): void
    {
        if (isset($_SESSION['cookie'])) return;
        $cookie = session_get_cookie_params();
        $_SESSION['cookie'] = [
            'originalMaxAge' => $this->config['cookie']['maxage'],
            'httpOnly' => $cookie['httponly'],
            'domain' => $cookie['domain'],
            'path' => $cookie['path'],
        ];
        if (!empty($this->config['cookie']['expires']))
            $_SESSION['cookie']['expires'] = $this->config['cookie']['expires'];
    }


	/**
	 * @param Countable&Iterator $value
	 * @return never
	 */
	protected function _mongo_handler(Iterator&Countable $value): never {
		// @todo
		exit();
	}
}


#EOF#
