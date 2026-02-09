// CVL 2.0 Specification for VulnerableBank
// Using Certora BUILT-IN RULES only - no custom rules needed!

use builtin rule sanity;
use builtin rule viewReentrancy;
use builtin rule hasDelegateCalls;
use builtin rule msgValueInLoopRule;
