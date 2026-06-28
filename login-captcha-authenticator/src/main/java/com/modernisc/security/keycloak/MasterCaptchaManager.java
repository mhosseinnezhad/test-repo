package com.modernisc.security.keycloak;

import cn.apiclub.captcha.Captcha;
import cn.apiclub.captcha.backgrounds.FlatColorBackgroundProducer;
import cn.apiclub.captcha.text.renderer.ColoredEdgesWordRenderer;

import javax.imageio.ImageIO;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class MasterCaptchaManager {

    private static int _width = 200;
    private static int _height = 50;
    private static final List<Color> COLORS = new ArrayList(2);
    private static final List<Font> FONTS = new ArrayList(3);
    private static final ColoredEdgesWordRenderer wordRenderer;


    static {
        COLORS.add(Color.decode("#09285d"));
        COLORS.add(Color.decode("#5d0909"));
        FONTS.add(new Font("Geneva", Font.BOLD, 48));
        FONTS.add(new Font("Courier", Font.BOLD, 48));
        FONTS.add(new Font("Arial", Font.BOLD, 48));

        wordRenderer = new ColoredEdgesWordRenderer(COLORS, FONTS);
    }

    public static Captcha generateNewCaptcha() {
        Captcha captcha = (new Captcha.Builder(_width, _height))
                .addText(wordRenderer)
                .gimp()
                .addNoise()
                .addBackground(new FlatColorBackgroundProducer(Color.decode("#e0e0e0")))
                .build();

        return captcha;
    }

    public static String captchaImageToString(Captcha captcha) throws IOException {

        byte[] imgBytes = new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(captcha.getImage(), "png", out);
        imgBytes = out.toByteArray();
        byte[] imgBytesAsBase64 = Base64.getEncoder().encode(imgBytes);
        String imgDataAsBase64 = new String(imgBytesAsBase64);
        String imgAsBase64 = "data:image/png;base64," + imgDataAsBase64;
        out.flush();

        return imgAsBase64;
    }
}
