<?php
namespace starekrow\Lockbox\tests;

require_once __DIR__ . "/../vendor/autoload.php";

use Exception;

class TestFramework_Fail extends Exception
{
}

class TestFramework
{
	private $_tf_want_exception;
	private $_tf_name;
	private $_tf_passed = 0;
	private $_tf_failed = 0;

	private function _tf_Begin( $name )
	{
		$n = substr( $name, strpos( $name, "_" ) + 1 );
		$re = '/(?#! splitCamelCase Rev:20140412)
		    # Split camelCase "words". Two global alternatives. Either g1of2:
		      (?<=[a-z])      # Position is after a lowercase,
		      (?=[A-Z])       # and before an uppercase letter.
		    | (?<=[A-Z])      # Or g2of2; Position is after uppercase,
		      (?=[A-Z][a-z])  # and before upper-then-lower case.
		    /x';
		$this->_tf_name = $n = implode( " ", preg_split($re, $n) );
		echo "[      ] " . $n;
		fflush( STDOUT );
	}

	private function _tf_Success()
	{
		++$this->_tf_passed;
		echo str_repeat( "\x08", strlen( $this->_tf_name ) + 8 );
		echo " pass ] " . $this->_tf_name . "\r\n";
		fflush( STDOUT );
	}

	private function _tf_Fail( $message = null )
	{
		++$this->_tf_failed;
		echo str_repeat( "\x08", strlen( $this->_tf_name ) + 8 );
		echo "-FAIL-] " . $this->_tf_name . "\r\n";
		if (!$message)  $message = $this->_tf_fail_msg;
		if ($message) {
			echo "         Reason: $message\r\n";
		}
		fflush( STDOUT );		
	}

	public function FailMessage( $msg )
	{
		$this->_tf_fail_msg = $msg;
	}

	public function Check( $val, $msg = null )
	{
		if (!$val) {
			throw new TestFramework_Fail( $msg );
		}
	}

	public function RunAllTests()
	{
		$l = get_class_methods( $this );
		$tl = [];
		foreach ($l as $el) {
			if (preg_match( "/^t[0-9]*_/", $el )) {
				if ($el[1] == "_") {
					//$el = "t50_" . substr( $el, 2 );
				}
				$tl[] = $el;
			}
		}
		sort( $tl );
		echo "\r\n";
		foreach ($tl as $el) {
			$this->_tf_want_exception = null;
			$this->_tf_fail_msg = null;
			try {
				$this->_tf_Begin( $el );
				$res = $this->{$el}();
				if ($res === false) {
					$this->_tf_Fail();
				} else {
					$this->_tf_Success();
				}
			} catch (\TestFramework_Fail $e) {
				$this->_tf_Fail( $e->getMessage() );
			} catch (\Exception $e) {
				if ($this->_tf_want_exception) {
					if ($e instanceof $this->_tf_want_exception) {
						$this->_tf_Success();
					} else {
						$this->_tf_Fail( "Unexpected " . get_class( $e ) );
					}
				} else {
					$this->_tf_Fail( "Unexpected " . get_class( $e ) );
				}
			} //PHP 7 only: } catch (FatalException $e) { .. .}
		}
		if ($this->_tf_failed) {
			echo "\r\nFAILED\x07 " . $this->_tf_failed . " of " . 
				($this->_tf_passed + $this->_tf_failed) . " tests\r\n\r\n";
		} else {
			echo "\r\nPassed " . $this->_tf_passed . " tests\r\n\r\n";
		}
	}
}
