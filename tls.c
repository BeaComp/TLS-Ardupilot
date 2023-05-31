
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include	"unp.h"
#include	<cyassl/ssl.h>

void SocketAPM::sig_handler(){
    printf("\nSIGINT handled.\n");
	wolfSSL_Cleanup();			/* Free wolfSSL */

    /* We can't free the WOLFSSL_CTX here because the 'ctx' variable is
       out of scope.  As such, we let the OS free this resource when the
       program terminates. */

    exit(EXIT_SUCCESS);
}


    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

void SocketAPM::initTLS()
{
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX structure */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
    {
        fprintf(stderr, "SSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }
}

void SocketAPM::startTLS()
{
    int sockfd;
    struct sockaddr_in servaddr;

    signal(SIGINT, sig_handler);

    if ((ssl = wolfSSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }

    wolfSSL_set_fd(ssl, sockfd);

    sockfd = socket(AF_INET, _datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    Inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

    /* Connect to socket file descriptor */
    Connect(sockfd, (SA *)&servaddr, sizeof(servaddr));

    str_cli(stdin, ssl);

    wolfSSL_free(ssl);          /* Free SSL object */
	CyaSSL_CTX_free(ctx);       /* Free SSL_CTX object */
	CyaSSL_Cleanup();           /* Free wolfSSL */

	exit(EXIT_SUCCESS);
}

void SocketAPM::star_cli(FILE *fp, WOLFSSL* ssl)
{
    char	sendline[MAXLINE], recvline[MAXLINE];
	int		n = 0;

	char sendline[MAXLINE];

    while (fgets(sendline, MAXLINE, fp) != NULL) {
        size_t len = strlen(sendline);
        if (wolfSSL_write(tls, sendline, len) != len) {
            err_sys("wolfSSL_write failed");
        }

        if ((n = wolfSSL_read(ssl, recvline, MAXLINE)) <= 0)
			err_quit("wolfSSL_read error");

		recvline[n] = '\0';
		Fputs(recvline, stdout);
    }

}

//Fazer a verificação de certificados

