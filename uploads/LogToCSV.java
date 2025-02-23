import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogToCSV extends JFrame {

    // Regex pattern to match the relevant ML-Agents log lines
    // Matches lines like:
    // [INFO] SoccerTwos. Step: 10000. Time Elapsed: 86.372 s. Mean Reward: 0.000. Mean Group Reward: -0.462. Training. ELO: 1198.258.
    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^\\[INFO\\]\\s+SoccerTwos\\.\\s+" +
                    "Step:\\s+(\\d+)\\.\\s+" +
                    "Time\\s+Elapsed:\\s+([\\d\\.]+)\\s+s\\.\\s+" +
                    "Mean\\s+Reward:\\s+([\\d\\.-]+)\\.\\s+" +
                    "Mean\\s+Group\\s+Reward:\\s+([\\d\\.-]+)\\.\\s+" +
                    "Training(?:\\.\\s+ELO:\\s+([\\d\\.]+))?.*$"
    );

    // Text areas for user input (logs) and CSV output (preview)
    private JTextArea logInputArea;
    private JTextArea csvOutputArea;

    public LogToCSV() {
        super("ML-Agents Log to CSV Parser");

        // Configure the main window
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 600);
        setLocationRelativeTo(null); // Center on screen

        // Create panels
        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        // Create text areas
        logInputArea = new JTextArea("Paste your ML-Agents logs here...", 15, 50);
        csvOutputArea = new JTextArea("CSV preview will appear here...", 15, 50);

        // Make text areas scrollable
        JScrollPane scrollLogs = new JScrollPane(logInputArea);
        JScrollPane scrollCSV = new JScrollPane(csvOutputArea);

        // Create buttons
        JButton parseButton = new JButton("Parse Logs");
        JButton saveButton = new JButton("Save CSV");

        // Configure parse button action
        parseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                parseLogs();
            }
        });

        // Configure save button action
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveCSV();
            }
        });

        // Add buttons to panel
        buttonPanel.add(parseButton);
        buttonPanel.add(saveButton);

        // Layout the GUI
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollLogs, scrollCSV);
        splitPane.setDividerLocation(0.5); // 50% split

        mainPanel.add(splitPane, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add main panel to the frame
        setContentPane(mainPanel);
    }

    /**
     * Parse the logs from the input text area and display CSV in the output area.
     */
    private void parseLogs() {
        String[] lines = logInputArea.getText().split("\\r?\\n");
        StringBuilder sb = new StringBuilder();
        // Write CSV Header
        sb.append("Step,TimeElapsed_s,MeanReward,MeanGroupReward,ELO\n");

        for (String line : lines) {
            Matcher matcher = LOG_PATTERN.matcher(line);
            if (matcher.matches()) {
                String step           = matcher.group(1);
                String timeElapsed    = matcher.group(2);
                String meanReward     = matcher.group(3);
                String meanGroup      = matcher.group(4);
                String elo            = matcher.group(5);  // May be null

                if (elo == null) {
                    elo = ""; // leave blank if not present
                }

                sb.append(step).append(",")
                        .append(timeElapsed).append(",")
                        .append(meanReward).append(",")
                        .append(meanGroup).append(",")
                        .append(elo).append("\n");
            }
            // Else, ignore lines that don't match
        }

        csvOutputArea.setText(sb.toString());
    }

    /**
     * Save the CSV output to a user-chosen file.
     */
    private void saveCSV() {
        if (csvOutputArea.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No CSV data to save. Please parse logs first.",
                    "Warning",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save CSV File");
        int userSelection = fileChooser.showSaveDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(fileToSave)) {
                writer.write(csvOutputArea.getText());
                JOptionPane.showMessageDialog(this,
                        "CSV saved successfully!",
                        "Success",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        "Error saving file:\n" + ex.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            LogToCSV frame = new LogToCSV();
            frame.setVisible(true);
        });
    }
}