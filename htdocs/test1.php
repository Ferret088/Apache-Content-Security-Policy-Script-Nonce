<!DOCTYPE html>
<html>
    <head>
        
        <script nonce="qwei">
        if (window.testRunner)
            testRunner.dumpAsText();
        alert('PASS (1/2)');
        </script>
        <script nonce="qwei">
        alert('PASS (2/2)');
        </script>
        <script nonce="noncynonce noncynonce">
            alert('FAIL (1/3)');
        </script>
        <script>
            alert('FAIL (2/3)');
        </script>
        <script nonce="noncynonceno?">
            alert('FAIL (3/3)');
        </script>
    </head>
    <body>
        <p>
            This tests the effect of a valid script-nonce value. It passes if
            three console warnings are visible, and the two PASS alerts are
            executed.
        </p>
    </body>
</html>
