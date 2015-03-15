<?php
/*
 * This file is part of CWD Whois Bundle.
 *
 * (c)2014 Ludwig Ruderstaller <lr@cwd.at>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Cwd\WhoisBundle\Service;

/**
 * Class Whois
 *
 * @package Cwd\Bundle\WhoisBundle
 * @author  Ludwig Ruderstaller <lr@cwd.at>
 */
class Whois
{
    /**
     * @var string
     */
    protected $apiUrl = 'https://www.whoisxmlapi.com/whoisserver/WhoisService';

    /**
     * @var string
     */
    protected $username = null;

    /**
     * @var string
     */
    protected $password = null;

    /**
     * @var string
     */
    protected $outputFormat = 'json';

    /**
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        if ($username == null || $password == null) {
            throw new \InvalidArgumentException('Username or Password for Whois XML Api not set');
        }

        $this->username = $username;
        $this->password = $password;
    }

    /**
     * Get Whois info for Domain
     *
     * @param string $domain
     *
     * @return array
     */
    public function findDomain($domain)
    {
        return $this->call(array('domainName' => rawurlencode(filter_var($domain, FILTER_SANITIZE_URL))));
    }

    /**
     * Build url and call api
     *
     * @param array $params
     *
     * @return stdClass
     */
    protected function call(array $params = array())
    {
        $defaults = array(
            'username' => rawurlencode($this->username),
            'password' => rawurlencode($this->password),
            'outputFormat' => $this->outputFormat
        );

        $params = array_merge($defaults, $params);
        $url = $this->apiUrl.'?'.http_build_query($params);
        $data = file_get_contents($url);
        $data = json_decode($data);

        if (isset($data->ErrorMessage->msg)) {
            throw new WhoisException($data->ErrorMessage->msg);
        }

        if (!isset($data->WhoisRecord)) {
            throw new WhoisException('Invalid Response');
        }

        return $data->WhoisRecord;
    }
}
