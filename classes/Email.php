<?php 

namespace Classes; 

use PHPMailer\PHPMailer\PHPMailer;

class Email {
    protected $email;
    protected $nombre;
    protected $token;

    public function __construct($email, $nombre, $token)
    {
        $this->email = $email;
        $this->nombre = $nombre;
        $this->token = $token;
    }

    public function enviarConfirmacion() {
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->Host = 'smtp.mailtrap.io';
        $mail->SMTPAuth = true;
        $mail->Port = 2525;
        $mail->Username = 'cb3b81f0d8e6eb';
        $mail->Password = '3e05c8555f93c0';
        
        $mail->setFrom('cuentas@uptask.com');
        $mail->addAddress('cuentas@uptask.com', 'uptask.com');
        $mail->Subject = 'Confirma tu cuenta';
        
        $mail->isHTML(TRUE);
        $mail->CharSet = 'UTF-8';

        $contenido = '<html>'; 
        $contenido .= "<p><strong>Hola " . $this->nombre . "</strong> Has creado tu cuenta en UpTask, solo debes confirmarla en el siguiente enlace </p>";
        $contenido .= "<p>Presiona aquí: <a href='http://localhost:3000/confirmar?token=" . $this->token . "'>Confirmar cuenta</a></p>";
        $contenido .= "<p>Si tu no creaste esta cuenta, puees ignorar este mensaje</p>";
        $contenido .= '</html>';

        $mail->Body = $contenido;

        // Enviar el email
        $mail->send();
    }

    public function enviarInstrucciones() {
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->Host = 'smtp.mailtrap.io';
        $mail->SMTPAuth = true;
        $mail->Port = 2525;
        $mail->Username = 'cb3b81f0d8e6eb';
        $mail->Password = '3e05c8555f93c0';
        
        $mail->setFrom('cuentas@uptask.com');
        $mail->addAddress('cuentas@uptask.com', 'uptask.com');
        $mail->Subject = 'Restablece tu password';
        
        $mail->isHTML(TRUE);
        $mail->CharSet = 'UTF-8';

        $contenido = '<html>'; 
        $contenido .= "<p><strong>Hola " . $this->nombre . "</strong> Parece que has olvidado tu password, haz click en el siguiente enlace para recuperarlo </p>";
        $contenido .= "<p>Presiona aquí: <a href='http://localhost:3000/restablecer?token=" . $this->token . "'>Restablecer password</a></p>";
        $contenido .= "<p>Si tu no creaste esta cuenta, puees ignorar este mensaje</p>";
        $contenido .= '</html>';

        $mail->Body = $contenido;

        // Enviar el email
        $mail->send();
    }
}
     