import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Testrun {
    //工具类：获取一个字符串，查找这个字符串出现的次数;
    public static int getStringCount(String str, String key) {
        int count = 0;
        int index = 0;
        int num = str.indexOf(key);
        while ((index = str.indexOf(key,index)) != -1){
            index = index +key.length();
            count++;
        }
        return count;
    }

    //工具类：正则匹配函数
    public static String getregexp(String str, String pattern) {
        String result = null;
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(str);
        System.out.println(p+"匹配\n"+str);
        Boolean flag = m.find(); //注意find()函数特性，后续会从当前位置开始匹配
        if (flag){
            System.out.println("匹配成功");
            String regexstr = m.group(1);
            System.out.println(regexstr);
            result = regexstr;
        }
        return result;
    }

    // 工具类：执行命令
    public static String exec(String cmd,int timeOut) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec(cmd);
        boolean res = p.waitFor(timeOut, TimeUnit.SECONDS);
        if(!res) {
            return "Time out";
        }
        InputStream inputStream = p.getInputStream();
        byte[] data = new byte[1024];
        String result = "";
        while(inputStream.read(data) != -1) {
            result += new String(data,"GBK");
        }
        if (result == "") {
            InputStream errorStream = p.getErrorStream();
            while(errorStream.read(data) != -1) {
                result += new String(data,"GBK");
            }
        }
        return result;
    }

    //工具类：调用RegexStaticAnalysis
    public static int getresult(String Testregex) {
        int result = 0;
        if (Testregex.startsWith("^") || Testregex.endsWith("$")){
            Testregex = Testregex.replaceFirst("\\^",""); //去除^符号，避免redos检测器跳过
            Testregex = Testregex.replaceFirst("\\$",""); //去除$符号，避免redos检测器跳过
            System.out.println("清洗后："+Testregex);
        }
        String cmdline = "java -cp E:\\Hack\\Tool\\RegexStaticAnalysis\\target\\dependency-jars\\*;E:\\Hack\\Tool\\RegexStaticAnalysis\\target\\regex-static-analysis-1.0-SNAPSHOT.jar driver.Main --regex='" + Testregex + "'";
        System.out.println(cmdline);
        try {
            String res = Testrun.exec(cmdline, 20);
            System.out.println(res);
            BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(res.getBytes(Charset.forName("GBK"))), Charset.forName("GBK")));
            String line;
            //逐行读取结果
            while( (line = br.readLine()) != null){
                if (!line.trim().equals("") && line.contains("Vulnerable:")){ //定位漏洞结果行
                    int length = line.trim().length();
                    char num = line.charAt(length - 2);
                    if (num == '1') { //存在漏洞的
                        String flag = String.valueOf(num);
                        result = Integer.parseInt(flag);
                        System.out.println(Testregex+"的检测结果："+result);
                    }
                }
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static Map GetRegex(String Filepath,Map Vmap) throws FileNotFoundException {
        int Stmp = 0;
        String regexvalue = "";
        InputStreamReader isr = null;
        BufferedReader br = null;
        try{
            isr = new InputStreamReader(new FileInputStream(Filepath));
            br = new BufferedReader(isr);
            String str;
            //配置文件
            if (!Filepath.endsWith(".java")){
                int linenum = 0;   //第几行
                while ((str = br.readLine()) != null) {
                    linenum ++;
                    if (str.toLowerCase().contains("reg") || str.toLowerCase().contains("pattern")){
                        String pattern = ".*reg.*=(.*)";
                        System.out.println("命中匹配规则：\n");
                        regexvalue = getregexp(str,pattern);
                        if (regexvalue != null){
                            ArrayList<String> values = new ArrayList<String>();
                            Stmp = getresult(regexvalue);
                            System.out.println("目标字符串："+str+"\n行数："+linenum);
                            values.add(String.valueOf(Stmp)); //是否存在漏洞
                            values.add(String.valueOf(linenum)); //第几行
                            Vmap.put(regexvalue,values); //key=正则。value=是否存在漏洞以及第几行
                        }
                    }
                }
            }else {
                //代码文件
                int linenum2 = 0;
                // 通过readLine()方法按行读取字符串
                while ((str = br.readLine()) != null) {
                    linenum2++;
                    System.out.println("文件内容如下：\n");
                    System.out.println(linenum2+str);
                    if (str.toLowerCase().contains("@pattern") || str.toLowerCase().contains("matches") || str.toLowerCase().contains("pattern.compile")){
                        String pattern = ".*\"(.*)\"";
                        regexvalue = getregexp(str,pattern);
                        System.out.println(regexvalue);
                        if (regexvalue != null){
                            ArrayList<String> values = new ArrayList<String>();
                            Stmp = getresult(regexvalue);
                            System.out.println("目标字符串："+str+"行数："+linenum2);
                            values.add(String.valueOf(Stmp)); //是否存在漏洞
                            values.add(String.valueOf(linenum2)); //第几行
                            Vmap.put(regexvalue,values); //key=正则。value=是否存在漏洞以及第几行
                        }
                    }
                    //可能存在两个“”的情况
                    else if (str.toLowerCase().contains("replaceall") || str.toLowerCase().contains("replacefirst")){
                        int Qcount = getStringCount(str,"\"");
                        if (Qcount <= 2){
                            String pattern2 = ".*\"(.*)\"";
                            regexvalue = getregexp(str,pattern2);
                            if (regexvalue != null){
                                ArrayList<String> values = new ArrayList<String>();
                                Stmp = getresult(regexvalue);
                                System.out.println("目标字符串："+str+"行数："+linenum2);
                                values.add(String.valueOf(Stmp)); //是否存在漏洞
                                values.add(String.valueOf(linenum2)); //第几行
                                Vmap.put(regexvalue,values); //key=正则。value=是否存在漏洞以及第几行
                            }
                        }else{   //存在两个“”的情况
                            String pattern3 = ".*\\\"(.*)\".*\".*\"";
                            regexvalue = getregexp(str,pattern3);
                            if (regexvalue != null){
                                ArrayList<String> values = new ArrayList<String>();
                                Stmp = getresult(regexvalue);
                                System.out.println("目标字符串："+str+"行数："+linenum2);
                                values.add(String.valueOf(Stmp)); //是否存在漏洞
                                values.add(String.valueOf(linenum2)); //第几行
                                Vmap.put(regexvalue,values); //key=正则。value=是否存在漏洞以及第几行
                            }
                        }
                    }

                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // 统一在finally中关闭流，防止发生异常的情况下，文件流未能正常关闭
            try {
                if (br != null) {
                    br.close();
                }
                if (isr != null) {
                    isr.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println(Vmap);
        return Vmap;
    }

    private static void loadfile(File file) throws FileNotFoundException {
        Map Vmap = new HashMap(); //用于存放正则、是否存在漏洞、行号
        File[] fs = file.listFiles();
        for(File f:fs){
            if(f.isDirectory())	{loadfile(f);}//若是目录，则递归打印该目录下的文件
            if(f.isFile()){
                //若是文件，直接打印
                Vmap = GetRegex(f.getAbsolutePath(),Vmap);
                System.out.println("Loadfile:"+f.getAbsolutePath());
                System.out.println("Result:"+Vmap);
            }
        }//128.64.205.178
    }

    public static void main(String [] args) throws FileNotFoundException {
        Map Vmap = new HashMap(); //用于存放正则、是否存在漏洞、行号

        //String Testregex = "(a+)*"; //默认值
        String Path = "D:\\javawork\\RedosScanTool";
        File file = new File(Path);
        loadfile(file);
        //String linenum = "";
        //Vmap = GetRegex("D:\\javawork\\test.java",Vmap);
        //getregexp("@Pattern(regexp = \"^[A-Za-z0-9_]*$\")",".*\"(.*)\"");
    }

}
