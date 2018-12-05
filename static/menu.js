var result = document.querySelector('#ham-menu');
result.innerHTML = `
    <ul>
			<li><a href="/sqli_name">SQLインジェクション1</a><br></li>
			<li><a href="/nosqli_name">SQLインジェクション1できない版</a><br></li>
			<li><a href="/sqli_id">SQLインジェクション2</a><br></li>
			<li><a href="/nosqli_id">SQLインジェクション2できない版</a><br></li>
			<li><a href="/xss">XSS(GET)</a><br></li>
			<li><a href="/noxss">XSSできない版</a><br></li>
			<li><a href="/hredirect?redirect=/">オープンリダイレクト1</a><br></li>
			<li><a href="/redirect?redirect=/">オープンリダイレクト2</a><br></li>
			<li><a href="/ping1">安全でないコマンド実行</a><br></li>
			<li><a href="/ping2">たぶん安全なコマンド実行</a><br></li>
			<li><a href="/readfile">ディレクトリトラバーサル</a><br></li>
			<li><a href="/notraversal">ディレクトリトラバーサルできないファイル読み込み</a><br></li>
			<li><a href="/ssrf1">SSRF</a><br></li>
			<li><a href="/jwt">JSON Web Token</a><br></li>
    </ul>
`;
