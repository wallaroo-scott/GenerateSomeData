package local.wallaroo;

import org.apache.commons.cli.*;
// import org.json.simple.JSONArray;
// import org.json.simple.JSONObject;
// import com.google.gson.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.io.PrintWriter;

/*
This application creates randomized data in x rows(lines) by y columns(fields).  Default filename is "filename"
but could be adjusted.

Working on:  Zeek DNS format

Command Line Example:   mvn exec:java -Dexec.mainClass=local.wallaroo.App -Dexec.args="-fn test.text -d comma -l 100 -f 10"
*/

public class App
{
    //
    public static final Option ARG_FILENAME = new Option("fn", "filename",true, "Add custom output filename. Default:  filename");
    public static final Option ARG_LINES = new Option("l", "lines",true, "Set number of lines of data. Default: 10 (-lines = 10)");
    public static final Option ARG_FIELDS = new Option("f", "fields",true, "Set number of fields per line. Default: 10 (-fields = 10");
    public static final Option ARG_DATATYPE = new Option("dt", "datatype",false, "Set output type: default/zeekdns.");
    public static final Option ARG_PATH = new Option("p", "path",true, "Set the path.  Default:  /tmp/ (-path /tmp/output/)");
    public static final Option ARG_OUTPUT = new Option("o", "output",true, "Set the output to either delimiter or JSON.  (-output delimiter)");
    public static final Option ARG_DELIMITER = new Option("d", "delimiter",true, "Set delimiter if NOT JSON: Tab, Comma, Space. Default: tab (-delimiter comma)");
    public static final Option ARG_NESTED = new Option("n", "nested",true, "Set the nested object property (number of items in each value property) Default: 10");

    static int switchRandom;
    public static String collectInfo;
    public static String fileName;
    public static int fieldNumber = 24; // fields per line
    public static int dataAmount;  // number of lines
    public static int fullCount;
    public static String delimiter;
    public static String path;
    public static String delimiterVerbose;
    public static String emptyField = "(empty)";
    public static boolean delimiterOutput;
    public static int returnDateCount;
    public static int createRandomWordCount;
    public static int createRandomIPCount;
    public static int returnIntegerCount;
    public static int returnRandDoubleCount;
    public static int returnURLCount;
    public static int emptyFieldCount;
    public static int portNumberCount;
    public static int returnBoolCount;
    public static int returnVectorCount;

    private static FileWriter file;
        // public static Integer nestedValue;

    // public static ProgressBar pb = new ProgressBar("Progress", 100);

    public static void main( String[] args )  throws Exception {
        // CommandLineParser clp = new DefaultParser();
        // pb.start();
        Options options = new Options();
        options.addOption(ARG_FILENAME);
        options.addOption(ARG_DELIMITER);
        options.addOption(ARG_LINES);
        options.addOption(ARG_PATH);
        // options.addOption(ARG_OUTPUT);
        // options.addOption(ARG_NESTED);
        // options.addOption(ARG_FIELDS);
        // options.addOption(ARG_DATATYPE);

        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine cl = parser.parse(options, args);

            if (cl.getOptionValue("filename") != null) {
                fileName = cl.getOptionValue("filename");
            } else {
                fileName = "filename";
            }

            if (cl.getOptionValue("delimiter") != null) {
                delimiterVerbose = cl.getOptionValue("delimiter");
            } else {
                delimiterVerbose = "tab";
            }

            /*if (cl.getOptionValue("fields") != null) {
                fieldNumber = Integer.parseInt(cl.getOptionValue("fields"));
            } else {
                fieldNumber = 10;
            }*/

            if (cl.getOptionValue("lines") != null) {
                dataAmount = Integer.parseInt(cl.getOptionValue("lines"));
            } else {
                dataAmount = 10;
            }

            if (cl.getOptionValue("path") != null) {
                path = cl.getOptionValue("path").toString() ;
            } else {
                path = "/tmp/box/";
            }

            switch (delimiterVerbose) {
                case "Tab":
                case "tab":
                    delimiter = "\t";
                    break;

                case "Comma":
                case "comma":
                    delimiter = ",";
                    break;

                case "Space":
                case "space":
                    delimiter = " ";
                    break;

                default:
                    showMessage("Delimiter not recognized", true);
                    printHelp(options);
                    break;
            }
            // int nodes = 2;
            System.out.println("Filename  : " + fileName);
            System.out.println("Path      : " + path);
            // System.out.println("Fields    : " + fieldNumber);
            System.out.println("Lines     : " + dataAmount);

            createDelimitedFile();
            System.out.println("Done");
            // pb.setExtraMessage("Finalizing....");
            // pb.stop();
            System.exit(0);
        }

        catch (Exception e) {
                System.out.println("Values Error");
                printHelp(options);
                e.printStackTrace();
                System.exit(-1);
            }
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        PrintWriter pw = new PrintWriter(System.out);
        pw.println("\nData Generator v.0.5");
        pw.println();
        formatter.printUsage(pw, 120, "java [-jar] DataGenerator[.java] [Option] ");
        formatter.printWrapped(pw, 120, "Example: java DataGenerator.java -fn filename.json -p /tmp/test -o json -d comma -f 100 -l 100 -dt default");
        pw.println();
        formatter.printOptions(pw, 120, options, 2, 6);
        pw.close();
    }

    public static void showMessage(String message, boolean exits) {
        System.out.println(message);
        if (exits) {
            System.out.println("Exiting...");
            System.exit(0);
        }
    }

    public static String createRandomWord(int len) {  // Convert to serial integer
        String name = "";
        for (int i = 0; i < len; i++) {
            int v = 1 + (int) (Math.random() * 26);
            char c = (char) (v + (i == 0 ? 'A' : 'a') - 1);
            name += c;
        }   return name;
    }

    public static String createRandomIP(int length) {
        Random r = new Random();
        return r.nextInt(length) + "." + r.nextInt(length) + "." + r.nextInt(length) + "." + r.nextInt(length);
    }

    public static int randBetween(int start, int end) {
        return start + (int)Math.round(Math.random() * (end - start));
    }

    public static String enumReturn(int enumType) {
        switch(enumType) {
            case 1:
                return "udp";
            case 2:
                return "tcp";
        }
        return "udp";
    }

    public static String returnBool() {
        int x;
        Random rand = new Random();
        x = rand.nextInt(2)+1;
        if (x==1) {return "true";}
        else {return "false";}
    }

    public static String returnIntegerVector(int vecLength) {
        String combined = "";
        for (int i=0; i < vecLength-1; i++) {
            combined += returnRandDouble(0.1,5.0)+",";
        }
        combined += returnRandDouble(0.1,5.0);
        return combined;
    }

    public static String returnStringVector(int vecLength) {
        String combined = "";
        for (int i=0; i < vecLength-1; i++) {
            combined += (createRandomWord(6)+",");
        }
        combined += (createRandomWord(6));
        return combined;
    }

    public static String returnDate() {
        String theDate;
        GregorianCalendar gc = new GregorianCalendar();
        int year = randBetween(1900, 2010);
        gc.set(gc.YEAR, year);
        int dayOfYear = randBetween(1, gc.getActualMaximum(gc.DAY_OF_YEAR));
        gc.set(gc.DAY_OF_YEAR, dayOfYear);
        theDate = ((gc.get(gc.MONTH)+1) + "-" + (gc.get(gc.DAY_OF_MONTH)) + "-" + gc.get(gc.YEAR));
        return theDate;
    }

    public static String returnInteger(int portMax) {
        int portNum;
        Random randPort = new Random();
        portNum = randPort.nextInt(portMax);
        return (String.valueOf(portNum));
    }

    public static String returnRandDouble(double min, double max) {
        double random = ThreadLocalRandom.current().nextDouble(min, max);
        String s = String.format("%.4f",random);
        return s;
    }

    public static String writeInfoDelimiter() {
        collectInfo =   "\n" +
                "# Lines of Data  : " + dataAmount + "\n" +
                //"# Fields in Each : " + fieldNumber + "\n" +
                "# Delimiter      : " + delimiterVerbose + "\n" +
                "# Filename       : " + fileName + "\n"  +
                "# Path           : " + path + "\n"  ;

        return collectInfo;
    }



    public static void createDelimitedFile () throws InterruptedException, IOException {
        String anim= "|/-\\";
        String header = "#separator \\x09\n" +
                "#set_separator\t,\n" +
                "#empty_field\t(empty)\n" +
                "#unset_field\t-\n" +
                "#path\tdns\n" +
                "#open\t2021-02-04-23-45-01\n" +
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n" +
                "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool";

        try {
            if(!path.endsWith("/"))
            {
                path = path + "/";
            }

            fileName = path + fileName;
            System.out.println("Writing to:  " + fileName);
            File directory = new File(path);
            if (!directory.exists()) {
                directory.mkdirs();
            }

            // String getInfo = writeInfoDelimiter();
            FileWriter writeFile = new FileWriter(fileName);
            System.out.println("Creating File...");

            writeFile.write(header + "\n");  // was getInfo
            Random rand  = new Random(2);
            for (int i = 1; i <= dataAmount; i++) {
                // for (int fields = 0; fields <= fieldNumber; fields++) {
                // 1
                returnRandDoubleCount += 1;
                fullCount +=1;
                writeFile.write(returnRandDouble(1612481111.1111, 1612489999.9999));
                writeFile.write(delimiter);

                // 2
                createRandomWordCount += 1;
                fullCount +=1;
                writeFile.write(createRandomWord(19));
                writeFile.write(delimiter);

                // 3
                createRandomIPCount += 1;
                fullCount +=1;
                writeFile.write(createRandomIP(250));
                writeFile.write(delimiter);

                // 4
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 5
                createRandomIPCount += 1;
                fullCount +=1;
                writeFile.write(createRandomIP(250));
                writeFile.write(delimiter);

                // 6
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 7
                portNumberCount += 1;
                fullCount +=1;
                writeFile.write(enumReturn(rand.nextInt()));
                writeFile.write(delimiter);

                // 8
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 9
                portNumberCount += 1;
                fullCount +=1;
                writeFile.write(returnRandDouble(0.01, 0.5));
                writeFile.write(delimiter);

                // 10
                createRandomWordCount += 1;
                fullCount +=1;
                writeFile.write(returnURL());
                writeFile.write(delimiter);

                // 11
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                //12
                createRandomWordCount += 1;
                fullCount +=1;
                writeFile.write(createRandomWord(19));
                writeFile.write(delimiter);

                // 13
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 14
                createRandomWordCount += 1;
                fullCount +=1;
                writeFile.write(createRandomWord(19));
                writeFile.write(delimiter);

                // 15
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 16
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));
                writeFile.write(delimiter);

                // 17
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));
                writeFile.write(delimiter);

                // 18
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));
                writeFile.write(delimiter);

                // 19
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));
                writeFile.write(delimiter);

                // 20
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));
                writeFile.write(delimiter);

                // 21
                returnIntegerCount += 1;
                fullCount +=1;
                writeFile.write(returnInteger(65000));
                writeFile.write(delimiter);

                // 22
                returnVectorCount += 1;
                fullCount +=1;
                writeFile.write(returnStringVector(3));
                writeFile.write(delimiter);

                // 23
                returnVectorCount += 1;
                fullCount +=1;
                writeFile.write(returnIntegerVector(3));
                writeFile.write(delimiter);

                // 24
                returnBoolCount += 1;
                fullCount +=1;
                writeFile.write(seqString(1));

                writeFile.write("\n");
                // }
            }


            // pb.setExtraMessage("Creating Report....");
            writeFile.write("\n");
            System.out.println("Closing File...");
            writeFile.close();
            // fileReport(fileName);
            System.out.println("\n");
            System.out.println("Metadata Report: \n");
            System.out.println("fullCount(true full)  :"+fullCount);
            System.out.println("createRandomWordCount :"+createRandomWordCount);
            System.out.println("createRandomIPCount   :"+createRandomIPCount);
            System.out.println("returnIntegerCount    :"+returnIntegerCount);
            System.out.println("returnRandDoubleCount :"+returnRandDoubleCount);
            System.out.println("returnURLCount        :"+returnURLCount);
            System.out.println("emptyFieldCount       :"+emptyFieldCount);
            System.out.println("portNumberCount       :"+portNumberCount);
            System.out.println("returnBoolCount       :"+returnBoolCount);
            System.out.println("returnVectorCount     :"+returnVectorCount);
            System.out.println("\n");
        }

        catch (IOException e)
        {
            showMessage("An error occurred writing the file.", false);
            e.printStackTrace();
            System.exit(-1);
        }
        showMessage("File Completed: " + fileName + "\n" + "Metadata File: " + fileName+".meta", true);
    }

    public static String seqString(int i) {
        return i < 0 ? "" : seqString((i / 26) - 1) + (char)(65 + i % 26);
    }



    public static String returnURL() {
        String[] urlList = {
                "blogger.com","cdc.gov","steampowered.com","clickbank.net","a8.net","tools.google.com","indiatimes.com","leparisien.fr","theatlantic.com","thestar.com",
                "google.com","independent.co.uk","alicdn.com","hollywoodreporter.com","calameo.com","developers.google.com","huffpost.com","instagram.com","pl.wikipedia.org","goal.com",
                "youtube.com","afternic.com","soundcloud.com","biglobe.ne.jp","thehill.com","brandbucket.com","goo.gl","doi.org","bp1.blogger.com","medicalnewstoday.com",
                "support.google.com","pixabay.com","sciencemag.org","rtve.es","behance.net","imdb.com","office.com","chicagotribune.com","tiktok.com","indianexpress.com",
                "microsoft.com","wsj.com","instructables.com","nationalgeographic.com","scoop.it","youronlinechoices.com","opera.com","akamaihd.net","skype.com","asus.com",
                "play.google.com","twitter.com","20minutos.es","prezi.com","searchenginejournal.com","creativecommons.org","msn.com","bloglovin.com","zendesk.com","slate.com",
                "apple.com","books.google.com","pbs.org","gmail.com","123rf.com","wikimedia.org","change.org","urbandictionary.com","nginx.org","ebay.de",
                "linkedin.com","abril.com.br","bitly.com","nikkei.com","ndtv.com","dailymotion.com","myaccount.google.com","freepik.com","welt.de","techradar.com",
                "en.wikipedia.org","draft.blogger.com","abcnews.go.com","springer.com","udemy.com","google.es","mediafire.com","plos.org","wix.com","investopedia.com",
                "cloudflare.com","rakuten.co.jp","yadi.sk","thenai.org","so-net.ne.jp","files.wordpress.com","washingtonpost.com","google.nl","eventbrite.com","fifa.com",
                "docs.google.com","express.co.uk","pinterest.fr","repubblica.it","greenpeace.org","google.de","cpanel.com","as.com","wikihow.com","mystrikingly.com",
                "wordpress.org","buydomains.com","groups.google.com","cnil.fr","eonline.com","live.com","ytimg.com","whitehouse.gov","stanford.edu","merriam-webster.com",
                "youtu.be","ipv4.google.com","webmd.com","cambridge.org","asahi.com","line.me","wikia.com","rapidshare.com","cbsnews.com","pinterest.co.uk",
                "maps.google.com","booking.com","over-blog.com","ea.com","ebay.co.uk","weebly.com","shutterstock.com","kickstarter.com","twitch.tv","imgur.com",
                "mozilla.org","amazon.co.jp","clarin.com","ikea.com","iubenda.com","yahoo.com","dailymail.co.uk","samsung.com","gnu.org","wn.com",
                "accounts.google.com","id.wikipedia.org","ovh.com","qq.com","inc.com","nih.gov","researchgate.net","npr.org","gov.br","sagepub.com",
                "bp.blogspot.com","amazon.es","outlook.com","tripadvisor.com","legifrance.gouv.fr","globo.com","google.it","ja.wikipedia.org","academia.edu","channel4.com",
                "drive.google.com","archive.org","it.wikipedia.org","rt.com","nl.wikipedia.org","paypal.com","fandom.com","akamaized.net","ca.gov","rambler.ru",
                "whatsapp.com","wp.com","vice.com","oracle.com","dribbble.com","bbc.co.uk","list-manage.com","mashable.com","francetvinfo.fr","sina.com.cn",
                "adobe.com","hugedomains.com","canva.com","discord.gg","unam.mx","enable-javascript.com","time.com","yahoo.co.jp","surveymonkey.com","zeit.de",
                "sites.google.com","terra.com.br","sapo.pt","news.com.au","adweek.com","who.int","un.org","gooyaabitemplates.com","sputniknews.com","fortune.com",
                "googleusercontent.com","marketingplatform.google....","unesco.org","lycos.com","wiktionary.org","policies.google.com","news.yahoo.com","britannica.com","ria.ru","mercurynews.com",
                "europa.eu","mirror.co.uk","netlify.app","thetimes.co.uk","faz.net","theguardian.com","bit.ly","abc.es","newyorker.com","sakura.ne.jp",
                "plus.google.com","plesk.com","e-recht24.de","disqus.com","corriere.it","w3.org","telegram.me","buzzfeed.com","insider.com","groups.yahoo.com",
                "github.com","namecheap.com","playstation.com","bing.com","focus.de","mail.google.com","aboutads.info","techcrunch.com","theverge.com","utexas.edu",
                "t.me","forms.gle","google.co.in","search.yahoo.com","steamcommunity.com","jimdofree.com","netvibes.com","alexa.com","wiley.com","airbnb.com",
                "es.wikipedia.org","estadao.com.br","bp2.blogger.com","php.net","about.me","cpanel.net","nasa.gov","ft.com","harvard.edu","vkontakte.ru",
                "istockphoto.com","dan.com","lavanguardia.com","washington.edu","google.com.au","google.co.jp","disney.com","discord.com","sciencedaily.com","pcmag.com",
                "vk.com","huffingtonpost.com","finance.yahoo.com","standard.co.uk","example.com","cnn.com","amzn.to","zoom.us","about.com","redhat.com",
                "vimeo.com","android.com","ted.com","photobucket.com","digitaltrends.com","ok.ru","offset.com","ebay.com","guardian.co.uk","twimg.com",
                "feedburner.com","nature.com","hm.com","adssettings.google.com","sky.com","fb.com","aol.com","photos1.blogger.com","nginx.com","ovh.co.uk",
                "facebook.com","scribd.com","berkeley.edu","cnbc.com","blackberry.com","t.co","ibm.com","gofundme.com","bild.de","livejournal.com",
                "uol.com.br","amazon.fr","mozilla.com","storage.googleapis.com","xing.com","google.pl","canada.ca","secureserver.net","googleblog.com","nokia.com",
                "amazon.com","usatoday.com","google.com.tw","netflix.com","lenta.ru","wired.com","engadget.com","cornell.edu","cbc.ca","salon.com",
                "search.google.com","ig.com.br","nypost.com","godaddy.com","yandex.com","picasaweb.google.com","newsweek.com","nydailynews.com","spotify.com","worldbank.org",
                "forbes.com","issuu.com","e-monsite.com","yelp.com","zdnet.com","de.wikipedia.org","ovh.net","hp.com","amazon.it","debian.org",
                "gravatar.com","networkadvertising.org","weibo.com","themeforest.net","google.co.id","shopify.com","economist.com","ietf.org","sfgate.com","dictionary.com",
                "news.google.com","businessinsider.com","calendar.google.com","picasa.google.com","kompas.com","pinterest.com","apache.org","oup.com","sedo.com","ucoz.ru",
                "bbc.com","4shared.com","gizmodo.com","zdf.de","bbci.co.uk","telegraph.co.uk","interia.pl","timeweb.ru","ziddu.com","hbr.org",
                "dropbox.com","amazon.co.uk","quora.com","lefigaro.fr","answers.com","hatena.ne.jp","sciencedirect.com","tmz.com","xbox.com","archives.gov",
                "myspace.com","foxnews.com","code.google.com","mega.nz","kotaku.com","mail.ru","google.ca","detik.com","wikipedia.org","billboard.com",
                "slideshare.net","google.ru","feedproxy.google.com","alibaba.com","usgs.gov","thesun.co.uk","mit.edu","t-online.de","icann.org","usda.gov",
                "gstatic.com","tinyurl.com","addtoany.com","xinhuanet.com","coursera.org","google.co.uk","lemonde.fr","m.wikipedia.org","variety.com","etsy.com",
                "nytimes.com","aliexpress.com","pexels.com","arxiv.org","si.edu","translate.google.com","psychologytoday.com","liberation.fr","dell.com","thoughtco.com",
                "google.com.br","photos.google.com","dw.com","sendspace.com","impress.co.jp","elpais.com","dailystar.co.uk","bandcamp.com","house.gov","public-api.wordpress.com",
                "reuters.com","cnet.com","yandex.ru","deezer.com","statista.com","ru.wikipedia.org","huawei.com","walmart.com","weforum.org","hindustantimes.com",
                "fr.wikipedia.org","amazon.de","ggpht.com","goodreads.com","politico.com","google.fr","naver.com","ign.com","lifehacker.com","namesilo.com",
                "pt.wikipedia.org","bloomberg.com","addthis.com","nbcnews.com","amazon.ca","elmundo.es","smh.com.au","abc.net.au","fda.gov","redbull.com",
                "medium.com","wa.me","privacyshield.gov","target.com","venturebeat.com","get.google.com","doubleclick.net","dreamstime.com","dreniq.com","mysql.com",
                "gov.uk","espn.com","spiegel.de","rollingstone.com","fb.me","latimes.com","imageshack.us","metro.co.uk","uefa.com","cbslocal.com"
        };

        Random randURL=new Random();
        int randomNumber=randURL.nextInt(urlList.length);
        return(urlList[randomNumber]);
    }
}