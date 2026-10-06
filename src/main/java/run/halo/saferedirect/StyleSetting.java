package run.halo.saferedirect;

import lombok.Data;

/**
 * 样式设置模型，对应 setting.yaml 中 group=style
 */
@Data
public class StyleSetting {
    private String theme = "default";
    private int countdown = 5;
    private boolean showTargetUrl = true;
    private boolean showQrCode = false;
    private String iconUrl = "";
    private String backgroundImageUrl = "";
    private String customHtml = "";
}
